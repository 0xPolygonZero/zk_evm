#!/bin/bash
set -e 
set -o pipefail

# Check if the correct number of arguments are provided
if [ "$#" -ne 10 ]; then
  echo "Usage: $0 <machine_type> <num_workers> <cpu_request> <cpu_limit> <memory_request> <memory_limit> <block_start> <block_end> <other_args> <rpc_endpoint>"
  exit 1
fi

# CONSTANTS
CLUSTER_NAME="immutable-prod"
NODE_POOL_NAME="immutable-prod-zk"
NAMESPACE="zkevm"
W_DEPLOYMENT_NAME="zero-bin-worker"
W_CONTAINER_NAME="worker"
L_DEPLOYMENT_NAME="zero-bin-leader"
L_CONTAINER_NAME="leader"
REGION="us-central1"
ZONE="us-central1-a"
W_DEPLOYMENT_LABEL="app.kubernetes.io/component=worker"
L_DEPLOYMENT_LABEL="app.kubernetes.io/component=leader"
LEADER_ENDPOINT="http://35.238.105.189:8080"
LOG_STRING_TO_WATCH_FOR="Finalized benchmarked proofs"
CPU_THRESHOLD=100
DISK_TYPE=""
NUM_WORKERS_LIMIT=200
IMX_RPC="http://35.208.84.178:8545"
INTERNAL_RPC="http://35.208.68.173:8545"
RPC_ADDRESS=""

# parameters
machine_type=$1
num_workers=$2
cpu_request=$3
cpu_limit=$4
memory_request=$5
memory_limit=$6
block_start=$7
block_end=$8
other_args=$9 # will be appended to the csv file name
RPC_ENDPOINT=${10}

######################
# Do some validation #
######################
if [[ "$num_workers" -gt $NUM_WORKERS_LIMIT ]]; then
  echo "error: Num workers can't be greater than ${NUM_WORKERS_LIMIT}" >&2
  exit 1
fi

re='^[0-9]+$'
if ! [[ $block_start =~ $re ]] ; then
   echo "error: Block start must be a number" >&2; exit 1
fi

if ! [[ $block_end =~ $re ]] ; then
   echo "error: Block end must be a number" >&2; exit 1
fi

if [[ $RPC_ENDPOINT == "IMX_RPC" ]]; then
  RPC_ADDRESS=$IMX_RPC
elif [[ $RPC_ENDPOINT == "INTERNAL_RPC" ]]; then
  RPC_ADDRESS=$INTERNAL_RPC
else
  echo "error: Wrong RPC endpoint" >&2; exit 1
fi

########################
# Update GKE node pool #
########################

if [[ "$machine_type" == *"n4"* ]]; then
  DISK_TYPE="hyperdisk-balanced"
else
  DISK_TYPE="pd-ssd"
fi

gcloud container node-pools update $NODE_POOL_NAME --cluster=$CLUSTER_NAME --machine-type=$machine_type --disk-type=$DISK_TYPE --region=$REGION

########################## 
# Get CPU family of node #
##########################

# Get the instance group URL for the node pool
INSTANCE_GROUP_URL=$(gcloud container node-pools describe "$NODE_POOL_NAME" --cluster "$CLUSTER_NAME" --location "$REGION" --format="json(instanceGroupUrls)" | jq -r '.instanceGroupUrls[0]')

# Extract the instance group name from the URL
INSTANCE_GROUP_NAME=$(basename "$INSTANCE_GROUP_URL")

# Get the name of one instance in the instance group
INSTANCE_NAME=$(gcloud compute instance-groups list-instances "$INSTANCE_GROUP_NAME" --zone "$ZONE" --format="value(instance)" | head -n 1)

# Get the CPU platform of the instance
CPU_PLATFORM=$(gcloud compute instances describe "$INSTANCE_NAME" --zone "$ZONE" --format='get(cpuPlatform)' | sed 's/\ /-/g')

########################
# Patch k8s deployment #
########################

# Export variables for envsubst
export REPLICAS=$num_workers W_CONTAINER_NAME CPU_REQUEST=$cpu_request MEMORY_REQUEST=$memory_request CPU_LIMIT=$cpu_limit MEMORY_LIMIT=$memory_limit

# Inline YAML content with placeholders
cat <<EOF | envsubst | kubectl patch deployment $W_DEPLOYMENT_NAME --patch "$(cat -)" --namespace=$NAMESPACE
spec:
  replicas: ${REPLICAS}
  template:
    spec:
      containers:
      - name: ${W_CONTAINER_NAME}
        resources:
          requests:
            cpu: "${CPU_REQUEST}"
            memory: "${MEMORY_REQUEST}"
          limits:
            cpu: "${CPU_LIMIT}"
            memory: "${MEMORY_LIMIT}"
EOF

# Wait for the deployment to finish
echo "Waiting for deployment $W_DEPLOYMENT_NAME to complete..."
kubectl rollout status deployment "$W_DEPLOYMENT_NAME" -n "$NAMESPACE"

if [ $? -ne 0 ]; then
  echo "Deployment $W_DEPLOYMENT_NAME failed to complete."
  exit 1
fi

echo "Deployment $W_DEPLOYMENT_NAME is complete."

# Need to wait for the worker pods to start generating circuits
sleep 60

#####################################
# Wait for CPU usage to steady down #
#####################################

echo "Waiting for CPU usage to steady down"

# Function to get the list of pod names based on label selector
get_pod_names() {
  kubectl get pods -n "$NAMESPACE" -l "$W_DEPLOYMENT_LABEL" -o jsonpath='{.items[*].metadata.name}'
}

check_cpu_usage() {
  local pod_names=($(get_pod_names))
  local all_below_threshold=true

  # Get metrics for all pods in the namespace
  local metrics=$(kubectl top pods -n "$NAMESPACE" -l "$W_DEPLOYMENT_LABEL" --no-headers)

  # Iterate through each pod's metrics
  while IFS= read -r line; do
    local pod_name=$(echo $line | awk '{print $1}')
    local cpu_usage=$(echo $line | awk '{print $2}' | sed 's/m//')

    # Check if the pod is part of the deployment
    if [[ " ${pod_names[@]} " =~ " ${pod_name} " ]]; then
      # Check if CPU usage is below the threshold
      if [ "$cpu_usage" -ge "$CPU_THRESHOLD" ]; then
        echo "Pod $pod_name CPU usage is $cpu_usage m, above threshold of $CPU_THRESHOLD m"
        all_below_threshold=false
      fi
    fi
  done <<< "$metrics"

  # Return true if all pods are below the threshold, false otherwise
  $all_below_threshold
}

while true; do
  if check_cpu_usage; then
    echo "All pods have CPU usage below $CPU_THRESHOLD m."
    break
  fi
  echo "Some pods have CPU usage above $CPU_THRESHOLD m. Checking again in 10 seconds..."
  sleep 10
done

######################
# Run benchmark test #
######################

# Build out the request parameters
csv_file_name=$(printf "%s.%s.%s.%s.%s.%scpu.%sworkers.csv" "$other_args" "$block_start" "$block_end" "$machine_type" "$CPU_PLATFORM" "$cpu_request" "$num_workers")
post_body=$(printf '{"block_interval":"%s..=%s","block_source":{"ZeroBinRpc":{"rpc_url":"%s"}},"benchmark_output":{"GoogleCloudStorageCsv":{"file_name":"%s","bucket":"zkevm-csv"}}}' "$block_start" "$block_end" "$RPC_ADDRESS" "$csv_file_name")

# Run the benchmark test
echo "Triggering benchmark test..."

curl -X POST $LEADER_ENDPOINT -H "Content-Type: application/json" -d "${post_body}"

echo "View logs at https://console.cloud.google.com/kubernetes/deployment/${REGION}/${CLUSTER_NAME}/zkevm/zero-bin-leader/logs?project=immutable-418115"

##############
# Watch logs #
##############

time_interval=60

#Watch logs and wait for the test to finish, then exit
check_logs() {
    pod=$(kubectl get pods -n "$NAMESPACE" -l $L_DEPLOYMENT_LABEL -o jsonpath='{.items[*].metadata.name}')

    echo "Checking logs for pod $pod in container $L_CONTAINER_NAME for the last ${time_interval}s"
    if kubectl logs -n "$NAMESPACE" "$pod" -c "$L_CONTAINER_NAME" --since="${time_interval}s" | grep -q "$LOG_STRING_TO_WATCH_FOR"; then
        echo "Found string '$LOG_STRING_TO_WATCH_FOR' in pod $pod logs"
        return 0
    fi

    return 1
}

while true; do
  if check_logs; then
    echo "String '$LOG_STRING_TO_WATCH_FOR' found. Exiting."
    break
  fi
  echo "String '$LOG_STRING_TO_WATCH_FOR' not found yet. Checking again in ${time_interval}s..."
  sleep $time_interval
done

echo "Benchmark test finished"
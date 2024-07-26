# expects GCS_UPLOAD_BUCKET environment variable
# optional GCS_UPLOAD_DIR environment variable
#   - if this one is not set, it will place the PGO file in the root of the bucket
# optional WORKER_RELATIVE_PATH environment variable
#   - if this one is not set, it will assume: `./target/x86_64-unknown-linux-gnu/release/worker`
# optional PROFILE_DIRECTORY environment variable
#   - if this one is not set, it will assume: `./target/pgo-profiles/`

import signal
import subprocess
import sys
import os
import time
from google.cloud import storage


GCS_UPLOAD_BUCKET = os.environ.get("GCS_UPLOAD_BUCKET")
assert(GCS_UPLOAD_BUCKET is not None)

# adds a trailing '/' if there wasn't one specified by the user
GCS_UPLOAD_DIR = os.environ.get("GCS_UPLOAD_DIR")
if GCS_UPLOAD_DIR is None:
    GCS_UPLOAD_DIR = ""
elif GCS_UPLOAD_DIR.endswith('/'):
    pass
else:
    GCS_UPLOAD_DIR += '/'

WORKER_PATH = os.environ.get("WORKER_PATH")
if WORKER_PATH is None:
    WORKER_PATH = "./target/x86_64-unknown-linux-gnu/release/worker"

PROFILE_DIRECTORY = os.environ.get("PROFILE_DIRECTORY")
if PROFILE_DIRECTORY is None:
    PROFILE_DIRECTORY = "./target/pgo-profiles/"

# upload the pgo file to the gcs bucket
def upload_pgo_file_to_gcs(file_path):
    print("Creating the GCS client...")
    storage_client = storage.Client(project="immutable-418115")

    # Get the bucket
    print("Connecting to the bucket...")
    bucket = storage_client.bucket(GCS_UPLOAD_BUCKET)

    print("Uploading the file to the bucket...")
    # Create a new blob and upload the file's content
    file_name = os.path.basename(file_path)

    upload_path = GCS_UPLOAD_DIR + file_name
    blob = bucket.blob(upload_path)
    blob.upload_from_filename(file_path)
    print("Finished. Shutting down...")

def cleanup_pgo_run():
    # continually checks if the PGO file has been generated before uploading to GCS
    print("Checking for a .profraw file...")
    files = os.listdir(PROFILE_DIRECTORY)
    while len(files) < 1:
        print("No .profraw file found. Waiting 1 second then checking again...")
        print("The profiling directory is:", PROFILE_DIRECTORY)
        time.sleep(1)
        files = os.listdir(PROFILE_DIRECTORY)

    if len(files) > 1:
        print("FATAL: more than 1 file in the profiling directory:", files)
        print("The profiling directory is:", PROFILE_DIRECTORY)
        print("Exiting...")
        sys.exit(1)
    else:
        print("Found the .profraw file. Uploading to GCS bucket:", GCS_UPLOAD_BUCKET)
        pgo_file = files[0]
        if pgo_file.endswith(".profraw"):
            full_pgo_file_path = PROFILE_DIRECTORY + "/" + pgo_file
            upload_pgo_file_to_gcs(full_pgo_file_path)
            sys.exit(0)
        else:
            print("FATAL: unexpected file extension (should be .profraw) in the profiling directory. File is:", pgo_file)
            print("The profiling directory is:", PROFILE_DIRECTORY)
            print("Exiting...")
            sys.exit(1)

# sends SIGTERM signals to the binary if SIGINT or SIGTERM are received.
#   NOTE: if you want to kill this wrapper instead of the inner binary, use SIGHUP or `kill -9`
def signal_handler(sig, frame):
    ''' for handling interrupts (currently SIGINT and SIGTERM) '''
    if sig == signal.SIGINT:
        print('Interrupted by user (SIGINT). Passing along a SIGTERM to pgo-worker instead...')
        process.send_signal(signal.SIGTERM)
        cleanup_pgo_run()
    elif sig == signal.SIGTERM:
        print('Termination signal received (SIGTERM). Passing it along to pgo-worker...')
        process.send_signal(signal.SIGTERM)
        cleanup_pgo_run()
    else:
        print("Ignoring an unexpected signal:", sig)
        return

# -------------------------
# | run the worker binary |
# -------------------------
process = subprocess.Popen(WORKER_PATH)

# register the signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# wait to receive a signal (ensures that the wrapper does not terminate)
while True:
    pass

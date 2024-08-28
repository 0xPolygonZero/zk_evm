searchState.loadedDescShard("mpt_trie", 0, "Utilities and types for working with Ethereum partial …\nA builder for constructing a partial trie from a …\nAdditional methods that may be useful when diagnosing …\nDefine <code>Nibbles</code> and how to convert bytes, hex prefix …\nDefinitions for the core types <code>PartialTrie</code> and <code>Nibbles</code>.\nSpecialized queries that users of the library may need …\nDefines various operations for <code>PartialTrie</code>.\nLogic for calculating a subset of a <code>PartialTrie</code> from an …\nVarious types and logic that don’t fit well into any …\nA builder for constructing a partial trie from a …\nBuilds the partial trie from the nodes and root.\nReturns the argument unchanged.\nInserts a proof into the builder.\nInserts variants of extension and leaf nodes into the …\nCalls <code>U::from(self)</code>.\nCreates a new <code>PartialTrieBuilder</code> with the given root and …\nDiffing tools to compare two tries against each other. …\nQuery tooling to report info on the path taken when …\nSimple tooling to extract stats from tries.\nA point (node) between the two tries where the children …\nMeta information for a node in a trie.\nThe difference between two Tries, represented as the …\nThe node info in the first trie.\nThe node info in the second trie.\nCreate a diff between two tries. Will perform both types …\nThe depth of the point in both tries.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nThe node key in both tries.\nThe highest point of structural divergence.\nThe path of the point in both tries.\nThe payload to give to the query function. Construct this …\nThe result of a debug query contains information of the …\nParams controlling how much information is reported in the …\nA wrapper for <code>DebugQueryParams</code>.\nBuilds a new debug query for a given key.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet debug information on the path taken when querying a …\nDefaults to <code>true</code>.\nDefaults to <code>false</code>.\nDefaults to <code>true</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nInformation on the comparison between two tries.\nStatistics for a given trie, consisting of node count …\nCompares with the statistics of another trie.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns trie statistics consisting of node type counts as …\nReturns trie statistics with a given name.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nErrors encountered when converting from <code>Bytes</code> to <code>Nibbles</code>.\nErrors encountered when converting to hex prefix encoding …\nThe hex prefix encoding flag is invalid.\nMaximum value.\nA Nibble has 4 bits and is stored as <code>u8</code>.\nA sequence of nibbles which is used as the key type into …\nLittle-endian large integer type Used for the internal …\nError type for conversion.\nOverflow encountered.\nAn error encountered when converting a string to a …\nBecause there are two different ways to convert to <code>Nibbles</code>…\nThe hex prefix encoding is too large.\nThe slice is too large.\nThe size is zero.\nComputes the absolute difference between self and other.\nReturns a slice of the internal bytes of packed nibbles. …\nConversion to u128 with overflow checking\nConversion to u32 with overflow checking\nConversion to u64 with overflow checking\nConversion to usize with overflow checking\nReturn if specific bit is set.\nReturn the least number of bits needed to represent the …\nReturn specific byte.\nReturns the nibbles bytes in big-endian format.\nChecked addition. Returns <code>None</code> if overflow occurred.\nChecked division. Returns <code>None</code> if <code>other == 0</code>.\nChecked multiplication. Returns <code>None</code> if overflow occurred.\nChecked negation. Returns <code>None</code> unless <code>self == 0</code>.\nChecked exponentiation. Returns <code>None</code> if overflow occurred.\nChecked modulus. Returns <code>None</code> if <code>other == 0</code>.\nChecked subtraction. Returns <code>None</code> if overflow occurred.\nThe number of nibbles in this sequence.\nReturns a pair <code>(self / other, self % other)</code>.\nCreate <code>10**n</code> as this type.\nFinds the nibble idx that differs between two nibbles. If …\nFinds the nibble index that differs between two <code>Nibbles</code> of …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nConverts from big endian representation bytes in memory.\nCreates <code>Nibbles</code> from big endian bytes.\nCreates <code>Nibbles</code> from little endian bytes.\nConvert from a decimal string.\nCreates <code>Nibbles</code> from a big endian <code>H256</code>.\nCreates <code>Nibbles</code> from a little endian <code>H256</code>.\nConverts a hex prefix byte string (“AKA “compact”) …\nConverts from little endian representation bytes in memory.\nCreates a new <code>Nibbles</code> from a single <code>Nibble</code>.\nParses a hex string with or without a preceding “0x”.\nConverts a string slice in a given base to an integer. …\nGets the next <code>n</code> nibbles.\nGets the nth proceeding nibble. The front <code>Nibble</code> is at idx …\nGets the nibbles at the range specified, where <code>0</code> is the …\nReturns the minimum number of nibbles needed to represent …\nCompute the highest <code>n</code> such that <code>n * n &lt;= self</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns whether or not this <code>Nibbles</code> contains actual …\nWhether this is zero.\nReturns the number of leading zeros in the binary …\nLow 2 words (u128)\nConversion to u32\nLow word (u64)\nThe maximum value which can be inhabited by this type.\nMerge a single Nibble with a <code>Nibbles</code>. <code>self</code> will be the …\nMerge two <code>Nibbles</code> together. <code>self</code> will be the prefix.\nReturns the minimum number of bytes needed to represent …\nCreate <code>Nibbles</code> that is empty.\nChecks if two given <code>Nibbles</code> are identical up to the …\nOne (multiplicative identity) of this type.\nAddition which overflows and returns a flag if it does.\nMultiply with overflow, returning a flag if it does.\nNegation with overflow.\nFast exponentiation by squaring. Returns result and …\nSubtraction which underflows and returns a flag if it does.\nA packed encoding of these nibbles. Only the first (least …\nPops the nibble at the back (the last nibble).\nPops the nibble at the front (the next nibble).\nPops the next <code>n</code> nibbles from the back.\nPops the next <code>n</code> nibbles from the front.\nFast exponentiation by squaring …\nPushes a nibble to the back.\nPushes a nibble to the front.\nAppends <code>Nibbles</code> to the back.\nAppends <code>Nibbles</code> to the front.\nReverses the <code>Nibbles</code> such that the last <code>Nibble</code> is now the …\nAddition which saturates at the maximum value (Self::MAX).\nMultiplication which saturates at the maximum value..\nSubtraction which saturates at zero.\nSplits the <code>Nibbles</code> at the given index, returning two …\nSplit the <code>Nibbles</code> at the given index but only return the …\nSplit the <code>Nibbles</code> at the given index but only return the …\nWrite to the slice in big-endian format.\nConverts <code>Nibbles</code> to hex-prefix encoding (AKA “compact”…\nWrite to the slice in little-endian format.\nConvert the type to a sequence of nibbles.\nConvert the type to a sequence of nibbles but pad to the …\nReturns the number of trailing zeros in the binary …\nDrops the last <code>n</code> nibbles without mutation.\nDrop the last <code>n</code> nibbles.\nDrops the next <code>n</code> proceeding nibbles without mutation.\nDrop the next <code>n</code> proceeding nibbles.\nZero (additive identity) of this type.\nA branch node, which consists of 16 children and an …\nReplace <code>BranchNode</code> with an appropriate <code>ExtensionNode</code>\nAn empty trie.\nAn extension node, which consists of a list of nibbles and …\nThe digest of trie whose data does not need to be stored.\nA partial trie that lazily caches hashes for each node as …\nA leaf node, which consists of a list of nibbles and a …\nA partial trie, or a sub-trie thereof. This mimics the …\nHow to handle the following subtree on deletion of the …\nA trait for any types that are Tries.\nReturn an error.\nA simple PartialTrie with no hash caching. Note that while …\nPart of the trait that is not really part of the public …\nAlias for a node that is a child of an extension or branch …\nReturns <code>true</code> if the trie contains an element with the …\nDeletes a <code>Leaf</code> node or <code>Branch</code> value field if it exists.\nAdd more nodes to the trie through an iterator\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a node if it exists in the trie.\nGet the hash for the node.\nReturns the hash of the rlp encoding of self.\nInserts a node into the trie.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns an iterator over the trie that returns all …\nReturns an iterator over the trie that returns all keys …\nCreates a new partial trie from a node.\nCreates a new partial trie from a node with a provided …\nReturns an iterator over the trie that returns all values …\nThe child of this extension node.\nA slice containing the 16 children of this branch node.\nThe path of this extension.\nThe path of this leaf node.\nThe payload of this node.\nThe payload of this node\nAn iterator for a trie query. Note that this iterator is …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nReturns all nodes in the trie that are traversed given a …\nContains the error value\nFailed to insert a hash node into the trie.\nAn error that occurs when we attempted to collapse an …\nA part of a larger trie that we are not storing but still …\nAn error that occurs when a hash node is found during a …\nAn error that occurs when we encounter an non-existing …\nAn error that occurs when a hash node is found during an …\nContains the success value\nAn iterator that ranges over all the leafs and hash nodes …\nAn error type for trie operation.\nStores the result of trie operations. Returns a TrieOpError…\nA value in a trie.\nAn “entry” in a <code>PartialTrie</code>.\nOptionally returns references to the inner fields if this …\nOptionally returns mutable references to the inner fields …\nOptionally returns references to the inner fields if this …\nOptionally returns mutable references to the inner fields …\nCast a <code>ValOrHash::Hash</code> enum to the hash (<code>H256</code>). Panics if …\nCast a <code>ValOrHash::Val</code> enum to the value (<code>Vec&lt;u8&gt;</code>). Panics …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns the inner fields if this is a <code>ValOrHash::Hash</code>, …\nReturns the inner fields if this is a <code>ValOrHash::Val</code>, …\nReturns true if this is a <code>ValOrHash::Hash</code>, otherwise false\nReturns true if this is a <code>ValOrHash::Val</code>, otherwise false\nContains the error value\nContains the success value\nWe encountered a <code>hash</code> node when marking nodes during …\nThe output type of trie_subset operations.\nCreate a <code>PartialTrie</code> subset from a base trie given an …\nCreate <code>PartialTrie</code> subsets from a given base <code>PartialTrie</code> …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nBranch node.\nBranch node along with the nibble of the child taken.\nEmpty node.\nEmpty node.\nExtension node.\nExtension node along with the key piece of the node.\nHash node.\nHash node.\nTrait for a type that can be converted into a trie key (…\nLeaf node.\nLeaf node along with the key piece of the node.\nSimplified trie node type to make logging cleaner.\nA vector of path segments representing a path in the trie.\nMinimal key information of “segments” (nodes) used to …\nConversion from an <code>Iterator</code> within an allocator.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReconstruct the key of the type.\nGet an iterator of the individual path segments in the …\nGet the node type of the <code>TrieSegment</code>.\nCreates a value from an iterator within an allocator.")
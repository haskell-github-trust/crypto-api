As stated in the .cabal, crypto-api is an interface for use by crypto consumers
and crypto implementors.  If you build a traditional cryptographic primitive
(hash function, block cipher, etc) then please consider making it an instance
of the appropriate class such that users can easily move between
implementations or even algorithms.

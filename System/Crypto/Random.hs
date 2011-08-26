{-# LANGUAGE CPP, ForeignFunctionInterface, BangPatterns #-}
{-|
 Maintainer: Thomas.DuBuisson@gmail.com
 Stability: beta
 Portability: portable

 Obtain entropy from system sources.  This module is rather untested on Windows (or testers never provided feedback),
 though testing was requested from the community - please e-mail the maintainer with test results.
-}

module System.Crypto.Random {-# DEPRECATED "Use the 'entropy' package module System.Entropy instead" #-}
	(module System.Entropy) where

import System.Entropy

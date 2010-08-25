-- |NIST KAT files are composed of properties, such as:
--
-- >	[SHA-1]
-- >	[PredictionResistance = True]
-- >	[EntropyInputSize = 128]
--
-- and individual known answer tests using these properties, ex:
--
-- >	COUNT = 0
-- >	EntropyInput = 7
-- >	PersonalizationString =
-- >	Result = 8
-- >
-- >	COUNT = 1
-- >	EntropyInput = 4
-- >	PersonalizationString = 
-- >	Result = 2
--
-- Using 'many parseCategory' this input would be converted to a
-- single element list of 'TestCategory':
--
-- >	[([("SHA-1",""), ("PredictionResistance", "True"), ("EntropyInputSize", "128")],
-- >	  	[   [("COUNT", "0"), ("EntropyInput", "7"), ("PersonalizationString", ""), ("Result", "8")], 
-- >		  , [("COUNT", "1"), ("EntropyInput", "4"), ("PersonalizationString", ""), ("Result", "2")]])]
--
-- that is, a list of tuples, the first element is a list of properties (key/value pairs) and
-- the second element is a list of tests.  Each test is itself a list of records (key/value pairs).
-- Properties apply to all tests contained in the second element of the tuple.
module Test.ParseNistKATs
	( parseCategory, parseProperty
	, Properties, Record, NistTest, TypedTest, TestCategory
	, module Text.Parsec
	) where

import Text.Parsec
import Text.Parsec.ByteString


type Properties = [(String, String)]
type Record = (String, String)
type NistTest = [Record]
type TypedTest = (String, [NistTest])

type TestCategory = (Properties, [NistTest])

-- |parse a NIST KAT file
parseCategory :: Parser (Properties, [NistTest])
parseCategory = do
	optional skipComments
        ps <- many1 parseProperty
	many space
        rsA <- many parseRecord
        let rs = chunk ((== "COUNT") . fst) rsA
        return (ps, rs)
  where
  chunk f lst = let (a,b) = chunkAt f lst in filter (not . null) (a : b)
  chunkAt :: (a -> Bool) -> [a] -> ([a], [[a]])
  chunkAt _ [] = ([], [])
  chunkAt f (a:as) = 
	if f a
		then let (curr, other) = (chunkAt f as)
		     in ([], (a:curr) : other)
		 else let (curr,other) = chunkAt f as in (a:curr , other)

skipComments = many $ do
	optional (many space)
	skipComment
	optional (many space)

skipComment = do
	char '#'
	manyTill anyChar newline
	return ()

parseProperty :: Parser (String, String)
parseProperty = do
        char '['
        t1 <- token
	many space
        m <- optionMaybe (char '=')
        res <- case m of
                Nothing  -> return (t1, "")
                Just _ -> do
                        many space
                        t2 <- token
                        return (t1, t2)
	optional (many space)
	return res
  where
  token = manyTill anyChar (oneOf [']', ' ', '\t'])

-- |parse a property or record (count) of a NIST KAT file
parseRecord :: Parser Record
parseRecord = do
	many space
        t1 <- token
        many space
        char '='
        many (oneOf [' ', '\t', '\r'])
        t2 <- token
        many space
        return (t1, t2)
  where
  token = many alphaNum -- manyTill anyChar ((space >> return ()) <|> eof)


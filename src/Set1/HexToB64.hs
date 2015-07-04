module Set1.HexToB64 where

import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Base16 as B16
import Data.ByteString.Char8 (pack, unpack, null, ByteString)
import Prelude hiding (null)

hexToB64 :: String -> String
hexToB64 = unpack . B64.encode . fst . B16.decode . pack

toHex :: ByteString -> String
toHex = unpack . B16.encode

fromHex :: String -> Either String ByteString
fromHex s = let (a, b) = B16.decode (pack s)
            in if null b then Right a else Left "Un-even number of chars"

toB64 :: ByteString -> String
toB64 = unpack . B64.encode

fromB64 :: String -> Either String ByteString
fromB64 = B64.decode . pack . killWS
  where
    killWS ('\n':xs) = killWS xs
    killWS (' ':xs) = killWS xs
    killWS ('\t':xs) = killWS xs
    killWS (x:xs) = x:killWS xs
    killWS [] = []

fromHex' :: String -> ByteString
fromHex' = either error id . fromHex

fromB64' :: String -> ByteString
fromB64' = either error id . fromB64

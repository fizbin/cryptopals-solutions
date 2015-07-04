module Set1.RepeatingKeyXOR where

import Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString as B
import Set1.FixedXOR


encryptBB :: ByteString -> ByteString -> ByteString
encryptBB bKey bPText =
  let repCount = 1 + (B.length bPText `div` B.length bKey)
  in fixedXOR (B.concat $ replicate repCount bKey) bPText

encryptSB :: String -> ByteString -> ByteString
encryptSB = encryptBB . BC.pack

encryptBS :: ByteString -> String -> ByteString
encryptBS k = encryptBB k . BC.pack

encryptSS :: String -> String -> ByteString
encryptSS k = encryptBB (BC.pack k) . BC.pack

encrypt :: String -> ByteString -> ByteString
encrypt = encryptSB

testText :: String
testText = "Burning 'em, if you ain't quick and nimble\n\
           \I go crazy when I hear a cymbal"

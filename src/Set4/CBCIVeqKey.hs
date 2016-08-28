module Set4.CBCIVeqKey where

import Crypto.Cipher.AES (AES128)
import Crypto.Cipher.Types
import Crypto.Random
import Crypto.Error
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.Char as DC
import Data.Monoid
import qualified Set1.HexToB64 as H
import Set1.FixedXOR
import qualified Set2.ImplementCBC as CBC


mkOracles :: B.ByteString -> (String -> B.ByteString,
                              B.ByteString -> Either B.ByteString Bool)
mkOracles aesKey = (encryptedProfileFor, isAdmin)
  where
    cipher :: AES128
    CryptoPassed cipher = cipherInit aesKey
    
    isAdmin cText =
      case CBC.decryptIVPad cipher aesKey cText of
        Left _ -> Right False
        Right x -> if B.any (> 127) x then Left x
                   else Right $ ";admin=true;" `B.isInfixOf` x

    encryptedProfileFor userdata =
      CBC.encryptIVPad cipher aesKey (BC.pack $ profileFor userdata)

    profileFor :: String -> String
    profileFor userdata = "comment1=cooking%20MCss;userdata=" <>
                          concatMap escaper userdata <>
                          ";comment2=%20like%20a%20pound%20of%20bacon"
      where
        escaper :: Char -> String
        escaper x | x `elem` (";%="::String) = "%" <> H.toHex (BC.singleton x)
        escaper x | DC.ord x > 127 = "%" <> H.toHex (BC.singleton x)
        escaper x = [x]


attackOracles :: (String -> B.ByteString,
                  B.ByteString -> Either B.ByteString Bool) ->  B.ByteString
attackOracles (encryptor, decryptTest) =
  let longName = replicate 32 'A'
      cText = encryptor longName
      mangled = B.take 16 cText <> B.replicate 16 0 <> B.take 16 cText
        <> B.drop 48 cText
      Left leaked = decryptTest mangled
  in fixedXOR (B.take 16 leaked) (B.take 16 $ B.drop 32 leaked)

main :: IO ()
main = do
  aesKey <- getRandomBytes 16
  let oracles = mkOracles aesKey
  putStrLn ("AESKey is " ++ show aesKey)
  let attacked = attackOracles oracles
  putStrLn ("Attack result is " ++ show attacked)

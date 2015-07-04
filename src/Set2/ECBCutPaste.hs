module Set2.ECBCutPaste where

import Control.Applicative
import Control.Monad (when)
import Crypto.Cipher.AES
import Crypto.Cipher.Types
import Data.Char (chr, ord)
import Data.Map (Map)
import qualified Data.Map as M
import Data.Monoid
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString as B
import qualified Set1.HexToB64 as H
import qualified Set2.PKCS7Padding as P7
import qualified Set2.ECBDecryption as Detect
import qualified Set2.ECBCBCDetection as Detect

parseCookie :: String -> Map String String
parseCookie "" = M.empty
parseCookie s = let (piece, rest') = break (== '&') s
                    rest = if null rest' then "" else tail rest'
                    (k, v') = break (== '=') piece
                    v = if null v' then "" else tail v'
                    unescaped [] = ""
                    unescaped ('%':a:b:xs) = BC.unpack (H.fromHex' [a,b]) <>
                                             unescaped xs
                    unescaped (x:xs) = x : unescaped xs
                in parseCookie rest <> M.singleton (unescaped k) (unescaped v)

profileFor :: String -> String
profileFor email = "email=" <> concatMap escaper email <> "&uid=10&role=user"
  where
    escaper x | x `elem` "%&=" = "%" <> H.toHex (BC.singleton x)
    escaper x = [x]

mkOracles :: (BlockCipher c) =>
             c -> (String -> B.ByteString,
                   B.ByteString -> Maybe (Map String String))
mkOracles cipher = (encryptedProfileFor, decryptProfile)
  where
    encryptedProfileFor email = ecbEncrypt cipher $
                                P7.pad (blockSize cipher) $
                                BC.pack $ profileFor email
    decryptProfile bytes = (parseCookie . BC.unpack) <$>
                           P7.unpad (blockSize cipher) (ecbDecrypt cipher bytes)

generateAdminEP :: String -> (String -> B.ByteString)
                   -> Either String B.ByteString
generateAdminEP emailDomain oracle = do
  when (length newRole > myBlockSize) $
    Left "Block size too short for new role"
  let email = mkEmail "x"
      oracledUser = oracle email
      blocks = mkBlocks oracledUser
  return $ B.concat $ init blocks ++ [adminBlock]
  where
    (myBlockSize, prefixLen, suffixLen) =
      Detect.detectLengths (oracle . BC.unpack)
    mkBlocks bs = if B.null bs then []
                  else let (a, b) = B.splitAt myBlockSize bs
                       in a : mkBlocks b
    oldRole = "user" :: String
    newRole = "admin" :: String
    paddedEmail = replicate ((-prefixLen) `mod` myBlockSize) 'A' <>
                  BC.unpack (P7.pad myBlockSize $ BC.pack newRole) <>
                  "@" <> emailDomain
    adminBlock = mkBlocks (oracle paddedEmail) !!
                 (-((-prefixLen) `div` myBlockSize))
    mkEmail addr = if (length addr + 1 + length emailDomain + prefixLen
                       + suffixLen - length oldRole)
                      `mod` myBlockSize == 0
                   then addr <> "@" <> emailDomain 
                   else mkEmail ('a':addr)
    

module Set1.DetectAESInECBMode where

import Set1.HexToB64
import Control.Monad (foldM, liftM2)
import qualified Data.ByteString as B
import qualified Data.Set as S
import Crypto.Cipher.Types
import Crypto.Cipher.AES
import Control.Applicative

checkForBlockEQ :: Int -> B.ByteString -> Bool
checkForBlockEQ bSize bStr =
  findEQ S.empty (byKeySize bStr)
  where
    byKeySize b | B.null b = []
    byKeySize b = let (c, rest) = B.splitAt bSize b
                  in c : byKeySize rest
    findEQ _ [] = False
    findEQ s (x:_) | S.member x s = True
    findEQ s (x:xs) = findEQ (S.insert x s) xs

checkLine :: String -> IO (Maybe String)
checkLine hexStr = do
  bStr <- either fail return $ fromHex hexStr
  return $ if checkForBlockEQ (blockSize (undefined :: AES128)) bStr
           then Just hexStr
           else Nothing

answer :: IO (Maybe String)
answer = do
  contents <- readFile "static/8.txt"
  let hexLines = lines contents
  foldM (\a hexLine -> liftM2 (<|>) (pure a) (checkLine hexLine))
    Nothing hexLines

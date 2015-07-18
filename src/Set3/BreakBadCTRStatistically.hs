module Set3.BreakBadCTRStatistically where

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.ByteString (ByteString)
import Control.Applicative
import Set3.ImplementCTR (encrypt64)
import Set2.ECBCBCDetection (randomAES)
import Set1.HexToB64
import Set1.FixedXOR
import Set3.BreakBadCTR (showEm)
import qualified Set1.BreakRepeatingKeyXOR as Breaker

solve :: [ByteString] -> [ByteString]
solve [] = []
solve [x] = [x]
solve problems =
  let minLength = minimum (map B.length problems)
      processed = map (B.take minLength) problems
      dropProcessed = map (B.drop minLength) problems
      remaining = filter (not . B.null) dropProcessed
      rezip ("":as) bs = "" : rezip as bs
      rezip (_:as) (b:bs) = b : rezip as bs
      rezip [] _ = []
      rezip as [] = as
      myKey = if minLength == 0 then ""
              else fst $ Breaker.solveWithKeySize minLength
                   (B.concat processed)
  in zipWith B.append (map (fixedXOR myKey) processed) $
     rezip dropProcessed $ solve remaining

mkProblems :: IO [B.ByteString]
mkProblems = do
  content <- readFile "static/20.txt"
  let b64Lines = lines content
  plainTexts <- either fail return (mapM fromB64 b64Lines)
  -- mapM_ (putStrLn . BC.unpack) plainTexts
  cipher <- randomAES >>= either fail return
  return $ map (encrypt64 cipher 0) plainTexts

answer :: IO ()
answer = solve <$> mkProblems >>= showEm

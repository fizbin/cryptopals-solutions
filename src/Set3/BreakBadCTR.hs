module Set3.BreakBadCTR where

import qualified Data.ByteString as B
import Control.Applicative
import Control.Arrow (first)
import Data.Foldable (forM_)
import Data.Function
import Data.List
import qualified Data.Map as M
import Set3.ImplementCTR (encrypt64)
import Set2.ECBCBCDetection (randomAES)
import Set1.HexToB64
import Set1.FixedXOR

plainTexts :: [B.ByteString]
plainTexts = map fromB64' [
  "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ=="
  , "Q29taW5nIHdpdGggdml2aWQgZmFjZXM="
  , "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ=="
  , "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4="
  , "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk"
  , "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA=="
  , "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ="
  , "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA=="
  , "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU="
  , "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl"
  , "VG8gcGxlYXNlIGEgY29tcGFuaW9u"
  , "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA=="
  , "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk="
  , "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg=="
  , "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo="
  , "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
  , "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA=="
  , "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA=="
  , "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA=="
  , "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg=="
  , "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw=="
  , "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA=="
  , "U2hlIHJvZGUgdG8gaGFycmllcnM/"
  , "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w="
  , "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4="
  , "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ="
  , "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs="
  , "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA=="
  , "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA=="
  , "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4="
  , "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA=="
  , "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu"
  , "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc="
  , "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs"
  , "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs="
  , "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0"
  , "SW4gdGhlIGNhc3VhbCBjb21lZHk7"
  , "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw="
  , "VHJhbnNmb3JtZWQgdXR0ZXJseTo="
  , "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
  ]

showEm :: [B.ByteString] -> IO ()
showEm strs = let starti = 0 :: Int
              in forM_ (zip [starti..] strs) $ \(i, t) ->
                 putStrLn (show i ++ ". " ++ show t)

histogram :: [B.ByteString] -> Int -> IO ()
histogram strs position = do
  let applicable = filter ((> position) . B.length) strs
      bytes = map (B.head . B.drop position) applicable
      one = 1 :: Int
      mapped = foldr (\c m -> M.insert c (one + M.findWithDefault 0 c m) m)
               M.empty bytes
      sortMap = sortBy (flip compare `on` snd) $ M.toList mapped
  putStrLn $ "Total " ++ show (length bytes)
  print $ map (first B.singleton) sortMap

mkGuesser :: IO (Int -> B.ByteString -> [B.ByteString])
mkGuesser = do
  cipher <- randomAES >>= either fail return
  let cTexts = map (encrypt64 cipher 0) plainTexts
  return (doGuess cTexts)
  where
    doGuess cTexts n guess = do
      let keyStream = ((cTexts !! n) `fixedXOR` guess) `B.append` "\0\0\0\0"
      map (`fixedXOR` keyStream) cTexts



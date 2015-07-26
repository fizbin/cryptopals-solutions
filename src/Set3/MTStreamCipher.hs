module Set3.MTStreamCipher where

import Set3.ImplementMT19937
import Set2.ECBCBCDetection (randomInt)
import Set3.ImplementCTR (littleEndianBstr)
import Control.Arrow (first)
import Control.Applicative
import Crypto.Cipher.Types
import Crypto.Error
import Crypto.Random
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import Data.ByteString (ByteString)
import Data.Word
import Data.Time.Clock.POSIX

data MT19937Stream = MT19937Stream {_sTwister :: Twisted Word32,
                                    _sRemaining :: ByteString}

instance Cipher MT19937Stream where
  cipherKeySize _ = KeySizeEnum [2, 4]
  cipherInit key = CryptoPassed $ MT19937Stream
                   (newTwisted mt19937 $ fromBA $ BA.unpack key)
                   B.empty
    where
      fromBA :: [Word8] -> Word32
      fromBA [] = 0
      fromBA (a:as) = fromIntegral a + 256 * fromBA as
  cipherName _ = "MT19937"

instance StreamCipher MT19937Stream where
  streamCombine (MT19937Stream twister rest) plainText =
    if BA.length plainText <= BA.length rest
    then (BA.xor plainText rest,
          MT19937Stream twister (B.drop (BA.length plainText) rest))
    else let (pref, plainRest) = BA.splitAt (BA.length rest) plainText
             in first (BA.append (BA.xor pref rest)) $ go twister plainRest
    where
      go :: (BA.ByteArray a) => Twisted Word32 -> a -> (a, MT19937Stream)
      go t pt | BA.length pt > 4 = let (pt1, pt2) = BA.splitAt 4 pt
                                       (i, t') = pullTwisted t
                                       s = littleEndianBstr 4 (fromIntegral i)
                                   in first (BA.append (BA.xor pt1 s))
                                      (go t' pt2)
      go t pt = let (i, t') = pullTwisted t
                    (s, rest') = B.splitAt (BA.length pt)
                                 (littleEndianBstr 4 (fromIntegral i))
                in (BA.xor pt s, MT19937Stream t' rest')

makePuzzle1 :: IO (Int, B.ByteString)
makePuzzle1 = do
  keyN <- randomInt 0 $ fromIntegral (maxBound::Word16)
  let keyStr = littleEndianBstr 2 $ fromIntegral keyN
      CryptoPassed cipher = cipherInit keyStr :: CryptoFailable MT19937Stream
  prefixLength <- randomInt 5 20
  randomPrefix <- getRandomBytes prefixLength
  return (keyN,
          fst $ streamCombine cipher (B.append randomPrefix "AAAAAAAAAAAAAA"))

breakPuzzle1 :: B.ByteString -> Word16
breakPuzzle1 ct = head $ filter acceptable [minBound .. maxBound]
  where
    acceptable w = 
      let keyStr = littleEndianBstr 2 $ fromIntegral w
          CryptoPassed cipher =
            cipherInit keyStr :: CryptoFailable MT19937Stream
      in "AAAAAAAAAA" `B.isSuffixOf` fst (streamCombine cipher ct)

makePassResetToken :: IO ByteString
makePassResetToken = do
  let find :: CryptoFailable MT19937Stream -> IO MT19937Stream
      find (CryptoPassed a) = return a
      find (CryptoFailed err) = fail $ show err
  mcipher <- cipherInit <$> littleEndianBstr 4 <$> floor <$> getPOSIXTime
  cipher <- find mcipher
  chars <- getRandomBytes 8
  return $ fst $ streamCombine cipher (B.append chars (B.replicate 8 0))

isRecentMTOutput :: ByteString -> IO Bool
isRecentMTOutput str = do
  nowTime <- floor <$> getPOSIXTime
  return $ any isFromSeed [nowTime - 100 .. nowTime + 1]
  where
    isFromSeed seed = let mcipher = cipherInit $ littleEndianBstr 4 seed
                          cipher :: MT19937Stream
                          CryptoPassed cipher = mcipher
                          decrypted = fst $ streamCombine cipher str
                      in hasLowEntropyParts decrypted
    hasLowEntropyParts :: B.ByteString -> Bool
    hasLowEntropyParts str' = any (\x -> B.replicate 4 x `B.isInfixOf` str')
                              $ B.unpack str'

import           Data.Bits       (shiftL, shiftR, testBit, xor, (.&.))
import           Data.Char       (chr, digitToInt, intToDigit, ord)
import           Data.List.Split (chunksOf)
import           Data.Word       (Word8)
import           Test.HUnit

-- Set 1 • Challenge 1 • Convert hex to base64
--------------------------------------------------------------------------------
decodeHex :: String -> [Word8]
decodeHex =
  map (\[x, y] -> fromIntegral $ shiftL (digitToInt x) 4 + digitToInt y) .
  chunksOf 2

encodeHex :: [Word8] -> String
encodeHex =
  map (intToDigit . fromIntegral) .
  concatMap (\w -> [shiftR (w .&. 0xf0) 4, w .&. 0x0f])

decodeAscii :: String -> [Word8]
decodeAscii = map $ fromIntegral . ord

encodeAscii :: [Word8] -> String
encodeAscii = map $ chr . fromIntegral

encodeBase64 :: [Word8] -> String
encodeBase64 = pad . map (base64Digit . evalBits) . chunksOf 6 . bits
  where
    pad x
      | length x `mod` 4 == 3 = x <> "="
      | length x `mod` 4 == 2 = x <> "=="
      | otherwise = x
    bits = concatMap (\word -> map (testBit word) [7,6 .. 0])
    evalBits = sum . map fst . filter snd . zip [2 ^ p | p <- [5,4 .. 0]]
    base64Digit i =
      (['A' .. 'Z'] <> ['a' .. 'z'] <> ['0' .. '9'] <> ['+', '/']) !! i

testBase64Padding :: Test
testBase64Padding =
  TestCase $ do
    (encodeBase64 . decodeAscii $ "any carnal pleasure.") @?=
      "YW55IGNhcm5hbCBwbGVhc3VyZS4="
    (encodeBase64 . decodeAscii $ "any carnal pleasure") @?=
      "YW55IGNhcm5hbCBwbGVhc3VyZQ=="
    (encodeBase64 . decodeAscii $ "any carnal pleasur") @?=
      "YW55IGNhcm5hbCBwbGVhc3Vy"

challenge1 :: Test
challenge1 = TestCase $ (encodeBase64 . decodeHex $ hex) @?= base64
  where
    hex =
      "49276d206b696c6c696e6720796f757220627261696e206c" <>
      "696b65206120706f69736f6e6f7573206d757368726f6f6d"
    base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

-- Set 1 • Challenge 2 • Fixed XOR
--------------------------------------------------------------------------------
(.+.) :: [Word8] -> [Word8] -> [Word8]
(.+.) = zipWith xor

challenge2 :: Test
challenge2 =
  TestCase $
  encodeHex
    (decodeHex "1c0111001f010100061a024b53535009181c" .+.
     decodeHex "686974207468652062756c6c277320657965") @?=
  "746865206b696420646f6e277420706c6179"

--------------------------------------------------------------------------------
main :: IO ()
main = do
  _ <- runTestTT $ TestList [testBase64Padding, challenge1, challenge2]
  return ()

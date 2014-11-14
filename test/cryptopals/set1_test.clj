(ns cryptopals.set1-test
  (:require [clojure.test :refer :all]
            [clojure.string :as s]
            [clojure.java.io :as io]
            [cryptopals.set1 :refer :all]))

;; Challenge 1
;; http://cryptopals.com/sets/1/challenges/1/

(deftest test-challenge-1
  (let [input "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        output "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"]
    (testing "homemade b64 encoder"
      (is (= output (hex->b64 input))))
    (testing "java8 b64 encoder"
      (is (= output (b64-encode (hex->bytes input)))))))


;; Challenge 2
;; http://cryptopals.com/sets/1/challenges/2/

(deftest test-challenge-2
  (let [input (hex->bytes "1c0111001f010100061a024b53535009181c")
        key (hex->bytes "686974207468652062756c6c277320657965")
        output "746865206b696420646f6e277420706c6179"]
    (testing "single-xor encryption"
      (is (= output (bytes->hex (fixed-xor input key)))))))


;; Challenge 3
;; http://cryptopals.com/sets/1/challenges/3/

(deftest test-challenge-3
  (let [input (hex->bytes "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
        output "Cooking MC's like a pound of bacon"]
    (is (= output (bruteforce-single-byte-xor input)))))


;; Challenge 4
;; http://cryptopals.com/sets/1/challenges/4/

;; no test for this one...


;; Challenge 5
;; http://cryptopals.com/sets/1/challenges/5/

(deftest test-challenge-5
  (let [input (str->bytes "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
        key (str->bytes "ICE")
        output "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"]
    (is (= output (bytes->hex (encrypt-repeating-xor input key))))))


;; Challenge 6
;; http://cryptopals.com/sets/1/challenges/6/

(deftest test-challenge-6
  (testing "hamming distance"
    (is (= 37 (hamming-distance (str->bytes "this is a test") (str->bytes "wokka wokka!!!")))))
  (testing "transpose"
    (let [before [1 2 3 4 5 6]
          after [[1 4] [2 5] [3 6]]]
      (is (= after (transpose before 3))))))

(deftest test-challenge-9
  (is (= (map char
              (add-padding (str->bytes "YELLOW SUBMARINE") 20))
         '(\Y \E \L \L \O \W \space \S \U \B \M \A \R \I \N \E \ \ \ \))))

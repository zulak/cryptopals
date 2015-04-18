;; # Crypto Challenge Set 1
;;
;; This is the qualifying set. We picked the exercises in it to ramp
;; developers up gradually into coding cryptography, but also to
;; verify that we were working with people who were ready to write
;; code.
;;
(ns zulak.cryptopals.set1
  (:require [zulak.cryptopals.common :as common]
            [clojure.string :as s]
            [clojure.java.io :as io]))


;; ## Challenge 1 -- Convert hex to base64
;;
;; Convert a byte sequence to a Base64-encoded string representation.
;; [exercise](http://cryptopals.com/sets/1/challenges/1/)
;;
;; I originally tried to write a b64 encoder from scratch, but
;; figuring out the padding ended up being a pain in the ass. For the
;; sake of getting to more interesting problems, we're using the
;; Base64 support included in the Java stdlib.

(defn challenge-1 [byte-seq]
  (common/b64-encode byte-seq))


;; ## Challenge 2 -- Fixed XOR
;;
;; Write a function that takes two equal-length buffers and produces
;; their XOR combination.
;; [exercise](http://cryptopals.com/sets/1/challenges/2/)
;;
;; Because we don't have unsigned types in Java (and by extension in
;; Clojure), we need to use a wider type than a byte, so we also need
;; to mask out all but the first byte of each element in the
;; sequences.

(defn fixed-xor [input key]
  (map (fn [x y]
         (bit-xor (bit-and 0xff x) (bit-and 0xff y)))
       input key))

(defn challenge-2 [input key]
  (fixed-xor input key))


;; ## Challenge 3 -- Single-byte XOR cipher
;;
;; Decrypt a ciphertext that was "encrypted" by XOR'ing the message
;; with a single repeated byte. [exercise](http://cryptopals.com/sets/1/challenges/3/)
;;
;; We can brute-force the decrypted message by trying to decrypt the
;; message with all 256 possible keys and compute a score of the
;; resulting plaintext's similiarity to English. The key that produces
;; the highest-scoring plaintext is probably the correct key.

(defn- is-nonprintable? [c]
  ( or (< (int c) 32) (> (int c) 126)))

;; Compute a 'resembles English' score for the input string, based
;; on the frequency of letters in the string.
;;
;; Characters that occur frequently in English contribute a larger
;; number of points than infrequently used characters. Non-printable
;; characters incurr a heavy penalty on the string's score.
;;
;; The word freqency table was taken from
;; [wikipedia](http://en.wikipedia.org/wiki/Letter_frequency).
;;
(defn- score-string [str]
  (let [english-freq-table {\space 20,\e 15,\t 10,\a 8,\o 8,
                            \i 8,\n 6,\s 6,\h 6,\r 5,\d 4,
                            \l 4,\c 2,\u 2,\m 2,\w 2,\f 2,
                            \g 2,\y 1,\p 1,\b 1}
        scores (map (fn [c]
                      (if (is-nonprintable? c)
                        -100
                        (get english-freq-table c 0)))
                    (s/lower-case str))]
    (reduce + scores)))

(defn- create-all-possible [input]
  (for [x (range 1 255)]
    {:key x
     :str (common/bytes->ascii (fixed-xor input (repeat x)))}))

;; Here we compute and score all possible decryptions of the
;; ciphertext.
;;
;; The highest scoring (most likely) key will be the first element in
;; the returned sequence.
;;
(defn- score-all-single-byte-decrypts [input]
  (->> input
       (create-all-possible)
       (map #(assoc % :score (score-string (:str %))))
       (sort-by :score)
       (reverse)))

(defn bruteforce-single-byte-xor [input]
  (->> (score-all-single-byte-decrypts input)
       (first)
       (:str)))

(defn challenge-3 [input]
  (bruteforce-single-byte-xor input))


;; ## Challenge 4 -- Detect single-character XOR
;;
;; From an input file of ciphertexts, find the string that was
;; encrypted with a single-character XOR.
;; [exercise](http://cryptopals.com/sets/1/challenges/4/)

(defn challenge-4 []
  (let [strings (s/split (slurp (io/resource "4.txt")) #"\n")
        byte-strings (map common/hex->bytes strings)
        all-possibilities (->> byte-strings
                               (mapcat score-all-single-byte-decrypts)
                               (sort-by :score)
                               (reverse))]
    (println (first (map :str all-possibilities)))))


;; ## Challenge 5 -- Implement repeating-key XOR
;;
;; Sequentially apply each byte of the key to produce a repeating-key
;; XOR ciphertext.
;; [exercise](http://cryptopals.com/sets/1/challenges/5/)

;; Clojure's lazy-sequences makes this sort of thing easy. Here we
;; turn the key into an infinitely repeating byte sequence and use
;; `map` to step over both the infintie key sequence and the plaintext
;; sequence.
;;
(defn encrypt-repeating-xor [plaintext-bytes key-bytes]
  (let [key-seq (cycle key-bytes)]
    (map #(bit-xor % %2) plaintext-bytes key-seq)))

(defn challenge-5 [plaintext key]
  (let [plaintext-bytes (common/str->bytes plaintext)
        key-bytes (common/str->bytes key)]
    (encrypt-repeating-xor plaintext-bytes key-bytes)))

;; ## Challenge 6 -- Break repeating-key XOR
;;
;; There's a file here. It's been base64'd after being encrypted with
;; repeating-key XOR. Decrypt it.
;; [exercise](http://cryptopals.com/sets/1/challenges/6/)
;;
;;

;; I feel like there should be a more efficient way to accomplish
;; this... I wonder if it would be more efficient to turn this into a
;; binary sequence first and then reduce the bits?
(defn- count-high-bits
  "Count the number of high bits in a byte."
  [b]
  (loop [acc 0 rem b]
    (if (= rem 0)
      acc
      (recur (+ acc (bit-and rem 1)) (bit-shift-right rem 1)))))

(defn hamming-distance
  "Compuate the bitwise hamming distance between two byte-seqs;
  assumes both seqs are of equal size"
  [a b]
  {:pre [(= (count a) (count b))]}
  (reduce + (map #(count-high-bits (bit-xor % %2)) a b)))

;; For each KEYSIZE, take the first KEYSIZE worth of bytes, and the
;; second KEYSIZE worth of bytes, and find the edit distance between
;; them. Normalize this result by dividing by KEYSIZE.
;;
;; *This doesn't appear to be a very good way to
;; guess the key length. I wonder why the challenge suggested this
;; technique?*
;;
(defn- score-key-length [input key-length]
  (let [chunks (partition-all key-length input)
        a (first chunks)
        b (second chunks)]
    (double (/ (hamming-distance a b) key-length))))

;; The KEYSIZE with the smallest normalized edit distance is probably
;; the key. You could proceed perhaps with the smallest 2-3 KEYSIZE
;; values. Or take 4 KEYSIZE blocks instead of 2 and average the
;; distances.
;;
(defn- score-key-length-avg [input key-length]
  (let [chunks (partition-all key-length input)
        a (first chunks)
        b (nth chunks 1)
        c (nth chunks 2)
        d (nth chunks 3)
        fn-norm (fn [x y] (/ (hamming-distance x y) key-length))]
    ;; take the average hamming-distance between all 4 chunks
    (double (/ (+ (fn-norm a b) (fn-norm a c) (fn-norm a d) (fn-norm b c) (fn-norm b d) (fn-norm c d)) 6))))

(defn- guess-key-lengths
  "Guess key lengths based on minimum normalized hamming distances.
  Smaller scores are better."
  [input]
  (map :length
       (sort-by :score
                (map #(hash-map :length % :score (score-key-length-avg input %)) (range 2 41)))))

;; Now that you probably know the KEYSIZE: break the ciphertext into
;; blocks of KEYSIZE length.
;;
;; Now transpose the blocks: make a block that is the first byte of
;; every block, and a block that is the second byte of every block,
;; and so on. Now, solve each block as if it was single-character XOR.

(defn- find-best-key-for-block [block]
  (->> (score-all-single-byte-decrypts block)
       (first)
       (:key)))

(defn transpose [input block-size]
  (for [i (range 0 block-size)] (map #(nth % i) (partition block-size input))))

(defn- guess-key [input block-size]
  (let [blocks (transpose input block-size)]
    (map find-best-key-for-block blocks)))

;; For each block, the single-byte XOR key that produces the best
;; looking histogram is the repeating-key XOR key byte for that block.
;; Put them together and you have the key.

(defn- try-decrypt [input block-size]
  (let [key (guess-key input block-size)]
    {:key (common/bytes->ascii key)
     :msg (common/bytes->ascii (encrypt-repeating-xor input key))}))

(defn challenge-6 []
  (let [input (common/b64-slurp "6.txt")
        key-length (first (guess-key-lengths input))
        result (try-decrypt input key-length)]
    (println (str "Key: " (:key result)))
    (println (str "Length: " (count (:key result))))
    (println)
    (println (:msg result))
    result))


;; ## Challenge 7 -- AES in ECB mode
;;
;; Decrypt the Base64-encoded content of a file that has been
;; encrypted via AES-128 in ECB mode under the key.

(defn challenge-7 []
  (common/aes-ecb-decrypt (common/b64-slurp "7.txt") "YELLOW SUBMARINE"))


;; ## Challenge 8 -- Detect AES in ECB mode
;;
;; In this file are a bunch of hex-encoded ciphertexts. One of them
;; has been encrypted with ECB. Detect it.
;;
;; Remember that the problem with ECB is that it is stateless and
;; deterministic; the same 16 byte plaintext block will always produce
;; the same 16 byte ciphertext.

(defn- find-patterns [b]
  (let [block-freqs (frequencies (partition-all 16 b))
         counts (map second block-freqs)]
    (apply max counts)))

 (defn challenge-8 []
   (let [strings (s/split (slurp (io/resource "8.txt")) #"\n")
         byte-strings (map common/hex->bytes strings)]
     (->> byte-strings
          (filter (fn [x] (> (find-patterns x) 1)))
          (first)
          (common/bytes->hex))))

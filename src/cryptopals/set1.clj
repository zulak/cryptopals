(ns cryptopals.set1
  (:require [clojure.string :as s]
            [clojure.java.io :as io])
  (:import java.util.Base64))

(def common-english-words #{"the" "be" "to" "of" "and" "a" "in" "that"
"have" "I" "it" "for" "not" "on" "with" "he" "as" "you" "do" "at"
"this" "but" "his" "by" "from" "they" "we" "say" "her" "she" "or" "an"
"will" "my" "one" "all" "would" "there" "their" "what" "so" "up" "out"
"if" "about" "who" "get" "which" "go" "me" "when" "make" "can" "like"
"time" "no" "just" "him" "know" "take" "people" "into" "year" "your"
"good" "some" "could" "them" "see" "other" "than" "then" "now" "look"
"only" "come" "its" "over" "think" "also" "back" "after" "use" "two"
"how" "our" "work" "first" "well" "way" "even" "new" "want" "because"
"any" "these" "give" "day" "most" "us"})

;; this needs some tweaking:
;; adapted from http://en.wikipedia.org/wiki/Letter_frequency
(def english-freq-table {\space, 20
                         \e, 15
                         \t, 10
                         \a, 8
                         \o, 8
                         \i, 8
                         \n, 6
                         \s, 6
                         \h, 6
                         \r, 5
                         \d, 4
                         \l, 4
                         \c, 2
                         \u, 2
                         \m, 2
                         \w, 2
                         \f, 2
                         \g, 2
                         \y, 1
                         \p, 1
                         \b, 1})

(defn remove-linebreaks [str]
  (s/replace str #"\n" ""))

(defn str->bytes [str]
  (seq (. str getBytes)))

(defn hex->int [s]
  (Integer/parseInt s 16))

(defn int->hex [i]
  (format "%02x" i))

(defn hex->bytes [h]
  (let [octets (map #(apply str %) (partition-all 2 h))]
    (map #(Integer/parseInt % 16) octets)))

(defn bytes->hex [b]
  (apply str (map int->hex b)))

(defn bytes->ascii [b]
  (apply str (map char b)))


;; Challenge 1

(def ^:private b64-table (vec
                (concat
                 (map char
                      (concat
                       (range (int \A) (inc (int \Z)))
                       (range (int \a) (inc (int \z)))
                       (range (int \0) (inc (int \9)))))
                 [\+ \/])))


(defn- combine-bytes [bytes]
  (reduce #(+ (bit-shift-left % 8) %2) bytes))

;; this doesn't add padding
;; sounds like a problem for future matt...
(defn- chunk->b64 [chunk]
  (loop [c chunk acc []]
    (if (= (count acc) 4)
      (reverse acc)
      (do
        (let [sextet (bit-and c 0x3f)
              remainder (bit-shift-right c 6)
              b64-digit (get b64-table sextet)]
          (recur remainder (conj acc b64-digit)))))))

(defn hex->b64 [b]
  (let [chunks (map combine-bytes (partition-all 3 (hex->bytes b)))]
    (apply str (mapcat chunk->b64 chunks))))

;; Well, that was easier, although somewhat unsatisfying...

(defn b64-decode [^String b64-string]
  (seq (. (Base64/getDecoder) decode b64-string)))

(defn b64-encode [byte-seq]
  (. (Base64/getEncoder) encodeToString (byte-array byte-seq)))


;; Challenge 2

(defn fixed-xor [input key]
  (let [pairs (map vector input key)]
    (map #(bit-xor (first %) (last %)) pairs)))

;; Challenge 3

(defn- create-all-possible [input]
  (for [x (range 1 255)]
    {:key x :str (bytes->ascii (fixed-xor input (repeat x)))}))

(defn- is-nonprintable? [c]
  ( or (< (int c) 32) (> (int c) 126)))

(defn- count-english-words [str]
  (let [words (s/split str #"\s+")]
    (count (filter common-english-words words))))

(defn- is-english-plaintext? [str]
  (> (count-english-words str) 0))

(defn- score-string [str]
  (reduce +
          (map
           (fn [c]
             (if (is-nonprintable? c)
               -100
               (get english-freq-table c 0)))
           (s/lower-case str))))

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


;; challenge 4

(defn challenge-4 []
  (let [strings (s/split (slurp (io/resource "4.txt")) #"\n")
        byte-strings (map hex->bytes strings)
        all-possibilities (reverse (sort-by :score (mapcat score-all-single-byte-decrypts byte-strings)))]
    (println (first (map :str all-possibilities)))))


;; Challenge 5

(defn encrypt-repeating-xor [plaintext-bytes key-bytes]
  (let [key-seq (cycle key-bytes)]
    (map #(bit-xor % %2) plaintext-bytes key-seq)))


;; Challenge 6

(defn- count-high-bits
  "Count the number of high bits in a byte."
  [b]
  (loop [acc 0 rem b]
    (if (= rem 0)
      acc
      (recur (+ acc (bit-and rem 1)) (bit-shift-right rem 1)))))

(defn transpose [input block-size]
  (for [i (range 0 block-size)] (map #(nth % i) (partition block-size input))))

(defn hamming-distance
  "compute bitwise hamming distance between two byte-seqs; assumes both seqs are of equal size"
  [a b]
  (reduce + (map #(count-high-bits (bit-xor % %2)) a b)))

;; Interestingly, this is a completely terrible way to guess the key
;; length. Was the challenge lying when it suggested this?
(defn- score-key-length [input key-length]
  (let [chunks (partition-all key-length input)
        a (first chunks)
        b (second chunks)]
    (double (/ (hamming-distance a b) key-length))))

(defn- score-key-length-avg [input key-length]
  (let [chunks (partition-all key-length input)
        a (first chunks)
        b (nth chunks 1)
        c (nth chunks 2)
        d (nth chunks 3)
        fn-norm (fn [x y] (/ (hamming-distance x y) key-length))]
    (double (/ (+ (fn-norm a b) (fn-norm a c) (fn-norm a d) (fn-norm b c) (fn-norm b d) (fn-norm c d)) 6))))

(defn- guess-key-lengths
  "Guess key lengths based on minimum normalized hamming distances. Smaller scores are better"
  [input]
  (map :length
       (sort-by :score
                (map #(hash-map :length % :score (score-key-length-avg input %)) (range 2 41)))))

(defn- find-best-key-for-block [block]
  (->> (score-all-single-byte-decrypts block)
       (first)
       (:key)))

(defn- guess-key [input block-size]
  (let [blocks (transpose input block-size)]
    (map find-best-key-for-block blocks)))

(defn- try-decrypt [input block-size]
  (let [key (guess-key input block-size)]
    {:key (bytes->ascii key) :msg (bytes->ascii (encrypt-repeating-xor input key))}))

(defn run6 []
  (let [input (b64-decode (remove-linebreaks (slurp (io/resource "6.txt"))))
        key-length (first (guess-key-lengths input))
        result (try-decrypt input key-length)]
    (println (str "Key: " (:key result)))
    (println (str "Length: " (count (:key result))))
    (println (:msg result))))

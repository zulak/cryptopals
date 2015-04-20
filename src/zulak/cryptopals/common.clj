;; ## Common crypto helper functions
;;
;; This namespace contains assorted helper functions and utilities for
;; manipulating bits and bytes, reading b64 encoded inputs and
;; encrypting/decrypting messages.
;;
(ns zulak.cryptopals.common
  (:require [clojure.string :as s]
            [clojure.java.io :as io])
  (:import java.util.Base64
           (javax.crypto Cipher KeyGenerator SecretKey)
           (javax.crypto.spec SecretKeySpec)
           (java.security SecureRandom)))

;; A javax.crypto transform string for AES-ECB encryption without padding.
(def ^:private aes-ecb-transform "AES/ECB/NoPadding")

(defn remove-linebreaks
  "Remove all line-breaks from the input string. This is used when
  parsing challenge inputs which contain semantically unimportant
  linebreaks."
  [str]
  (s/replace str #"\n" ""))

(defn str->bytes
  "Convert a String into a sequence of bytes."
  [str]
  (vec (. str getBytes)))

(defn hex->int
  "Convert a String representation of a hexadecimal digit into an int."
  [s]
  (Integer/parseInt s 16))

(defn int->hex
  "Convert an int (<= 255) into its hexadecimal String representation."
  [i]
  (format "%02x" i))

(defn hex->bytes
  "Convert a hexadecimal string into a byte sequence."
  [h]
  (let [octets (map #(apply str %) (partition-all 2 h))]
    (vec (map #(Integer/parseInt % 16) octets))))

(defn bytes->hex
  "Convert a byte sequence into a hexadecimal string."
  [b]
  (apply str (map int->hex b)))

(defn- printable? [b]
  (when (number? b)
    (cond
      (= b 10) true
      (< b 31) false
      (> b 126) false
      :else true)))

(defn bytes->ascii
  "Convert a byte sequence into its string representation."
  [b]
  (->> (filter printable? b)
       (map char)
       (apply str)))

(defn b64-decode
  "Decode a Base64 encoded string into a sequence of bytes."
  [^String b64-string]
  (vec (. (Base64/getDecoder) decode b64-string)))

(defn b64-encode
  "Encode a byte sequence as a Base64 encoded string."
  [byte-seq]
  (. (Base64/getEncoder) encodeToString (byte-array byte-seq)))

(defn b64-slurp
  "Read a Base64 encoded input from disk, returning a byte sequence."
  [f]
  (b64-decode (remove-linebreaks (slurp (io/resource f)))))

(defn- get-ecb-cipher
  "Create a new Cipher instance configured for the AES ECB transformation."
  [mode key]
  (let [key-spec (SecretKeySpec. (byte-array key) "AES")
        cipher (Cipher/getInstance aes-ecb-transform)]
    (.init cipher mode key-spec)
    cipher))

(defn aes-ecb-encrypt
  "AES ECB encrypt a plaintext with the provided key, returning a ciphertext.

  The key and plaintext must be the same length."
  [text key]
  {:pre [(= (count text) (count key))]}
  (let [plaintext (byte-array text)
        cipher (get-ecb-cipher Cipher/ENCRYPT_MODE key)]
    (seq (.doFinal cipher plaintext))))

(defn aes-ecb-decrypt
  "AES ECB decrypt a ciphertext with the provided key, returning a plaintext.

  The key and ciphertext must be the same length."
  [text key]
  {:pre [(= (count text) (count key))]}
  (let [cipher (get-ecb-cipher Cipher/DECRYPT_MODE key)
        ciphertext (byte-array text)]
    (seq (.doFinal cipher ciphertext))))

(defn add-pkcs7-padding
  "Adds PKCS#7 padding to an irregularly-sized plaintext input, returning a padded plaintext whose size is a multiple of the specified block-size.

  *NB:* A plaintext that is a multiple of the block-size will be
  padded with an additional $BLOCK_SIZE bytes.

  See: [wikipedia](http://en.wikipedia.org/wiki/Padding_%28cryptography%29#PKCS7)"
  [block-size plaintext]
  (let [num-padding-bytes (- block-size (mod (count plaintext) block-size))
        result (vec plaintext)]
    (if (= num-padding-bytes block-size)
      (into result (repeat block-size block-size))
      (into result (repeat num-padding-bytes num-padding-bytes)))))

(defn- validate-pkcs7-padding
  [block-size plaintext-bytes]
  (let [count-expected-padding (last plaintext-bytes)]
    (when (and (<= count-expected-padding block-size)
               (>= (count plaintext-bytes) count-expected-padding)
               (apply = (take-last count-expected-padding plaintext-bytes)))
      count-expected-padding)))

(defn remove-pkcs7-padding
  [block-size plaintext-bytes]
  (if-let [padding-bytes (validate-pkcs7-padding block-size plaintext-bytes)]
    (drop-last padding-bytes plaintext-bytes)
    (throw (IllegalArgumentException. "input does not contain pkcs#7 padding"))))

(defn ecb-decrypt-msg
  "Decrypt a ECB-encrypted ciphertext using the provided key, returning a plaintext."
  [key ciphertext]
  (->> (partition-all 16 ciphertext)
       (mapcat (fn [x] (aes-ecb-decrypt x key)))
       (remove-pkcs7-padding 16)))

(defn ecb-encrypt-msg
  "Encrypt a plaintext with the provided key, returning a ciphertext.

  Padding is added automatically if required."
  [key plaintext]
  (mapcat (fn [x] (aes-ecb-encrypt x key)) (partition-all 16 (add-pkcs7-padding 16 plaintext))))

(defn get-random-key
  "Generate a random key of the specified length."
  [len]
  (repeatedly len #(rand-int 256)))

(ns zulak.cryptopals.set-test
  (:require [clojure.test :refer :all]
            [clojure.string :as s]
            [clojure.java.io :as io]
            [zulak.cryptopals.common :refer :all]
            [zulak.cryptopals.set2 :refer :all]))


(deftest test-challenge-9
  (is (= (map char
              (challenge-9 20 "YELLOW SUBMARINE"))
         '(\Y \E \L \L \O \W \space \S \U \B \M \A \R \I \N \E \ \ \ \))))

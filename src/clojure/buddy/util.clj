(ns buddy.util
  (:require [clojure.algo.monads :refer [domonad maybe-m]]))

(defmacro m-maybe
  "Simple helper for maybe monad."
  [bindings & body]
  `(domonad maybe-m
     ~bindings
     (do ~@body)))

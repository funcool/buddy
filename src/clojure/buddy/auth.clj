(ns buddy.auth
  (:import (buddy.exceptions NotAuthorizedException)))

(defn authenticated?
  "Test if a current request is
  authenticated or not."
  [request]
  (boolean (:identity request)))

(defn throw-notauthorized
  ([] (throw-notauthorized {}))
  ([metadata]
   (throw (NotAuthorizedException. metadata))))

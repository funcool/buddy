(ns buddy.auth.middleware
  (:require [buddy.auth.protocols :as proto]
            [buddy.auth :refer [authenticated?]]
            [buddy.util :refer [m-maybe]]
            [ring.util.response :refer [response response?]])
  (:import (buddy.exceptions NotAuthorizedException)))

(defn wrap-authentication
  "Ring middleware that enables authentication
  for your routes."
  [handler backend]
  (fn [request]
    (let [request (assoc request :auth-backend backend)
          rsq     (proto/parse backend request)]
      (if (response? rsq) rsq
        (if (nil? rsq)
          (handler request)
          (let [rsq (proto/authenticate backend request rsq)]
            (if (response? rsq) rsq
              (handler (or rsq request)))))))))

(defn wrap-authorization
  "Ring middleware that enables authorization
  workflow you your ring handler."
  [handler & [backend]]
  (fn [request]
    (let [backend (or backend (:auth-backend request))]
      (if (nil? backend)
        (throw (IllegalAccessError. "no backend found"))
        (try
          (handler request)
          (catch NotAuthorizedException e
            (proto/handle-unauthorized backend request (.getMetadata e))))))))

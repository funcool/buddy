(ns buddy.auth.middleware
  (:require [buddy.auth.protocols :as proto]
            [buddy.util :refer [m-maybe]]
            [ring.util.response :refer [response response?]]))

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

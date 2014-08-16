(ns buddy.test_buddy_auth
  (:require [clojure.test :refer :all]
            [ring.util.response :refer [response? response]]
            [buddy.core.codecs :refer :all]
            [buddy.sign.generic :as s]
            [buddy.auth :refer [throw-unauthorized]]
            [buddy.auth.backends.httpbasic :refer [http-basic-backend parse-httpbasic-header]]
            [buddy.auth.backends.session :refer [session-backend]]
            [buddy.auth.backends.token :as stoken]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]]))

(defn make-httpbasic-request
  [username, password]
  (if (and username password)
    {:headers {"authorization" (format "Basic %s" (str->base64 (format "%s:%s" username password)))}}
    {:headers {}}))

(defn httpbasic-auth-fn
  [request parsed-data]
  (let [username (:username parsed-data)]
    (cond
      (= username "foo") :foo)))

(def secret-key "test-secret-key")

(deftest http-basic-parse-test
  (testing "Parse httpbasic header from request"
    (let [header  (format "Basic %s" (str->base64 "foo:bar"))
          request {:headers {"authorization" header}}
          parsed  (parse-httpbasic-header request)]
      (is (not (nil? parsed)))
      (is (= (:password parsed) "bar"))
      (is (= (:username parsed) "foo")))))

(deftest token-test
  (let [authfn (fn [request token]
                 (get {:token1 {:userid 1}
                       :token2 {:userid 2}} (keyword token)))]
    (testing "Parse authorization header"
      (let [signed-data     (s/dumps {:userid 1} secret-key)
            header-content  (format "Token %s" signed-data)
            request         {:headers {"authorization" header-content}}
            parsed          (stoken/parse-authorization-header request)]
        (is (= parsed signed-data))))

    (testing "Signed token backend authentication"
      (let [signed-data     (s/dumps {:userid 1} secret-key)
            header-content  (format "Token %s" signed-data)
            request         {:headers {"authorization" header-content}}
            backend         (stoken/signed-token-backend {:privkey secret-key})
            handler         (-> (fn [req] req)
                                (wrap-authentication backend))
            resp            (handler request)]
        (is (= (:identity resp) {:userid 1}))))

    (testing "Signed token backend wrong authentication"
      (let [signed-data     (s/dumps {:userid 1} "wrong-key")
            header-content  (format "Token %s" signed-data)
            request         {:headers {"authorization" header-content}}
            backend         (stoken/signed-token-backend {:privkey secret-key})
            handler         (-> (fn [req] req)
                                (wrap-authentication backend))
            resp            (handler request)]
        (is (nil? (:identity resp)))))

    (testing "Signed token backend with wrong data"
      (let [header-content  "Token foobar"
            request         {:headers {"authorization" header-content}}
            backend         (stoken/signed-token-backend {:privkey secret-key})
            handler         (-> (fn [req] req)
                                (wrap-authentication backend))
            resp            (handler request)]
        (is (nil? (:identity resp)))))

  (testing "Signed token unathorized request 1"
    (let [signed-data     (s/dumps {:userid 1} secret-key)
          header-content  (format "Token %s" signed-data)
          request         {:headers {"authorization" header-content}}
          backend         (stoken/signed-token-backend {:privkey secret-key})
          handler         (-> (fn [req] (throw-unauthorized))
                              (wrap-authorization backend)
                              (wrap-authentication backend))
          resp            (handler request)]
      (is (= (:status resp) 403))))

  (testing "Signed token unathorized request 2"
    (let [signed-data     (s/dumps {:userid 1} "wrong-key")
          header-content  (format "Token %s" signed-data)
          request         {:headers {"authorization" header-content}}
          backend         (stoken/signed-token-backend {:privkey secret-key})
          handler         (-> (fn [req] (throw-unauthorized))
                              (wrap-authorization backend)
                              (wrap-authentication backend))
          resp            (handler request)]
      (is (= (:status resp) 401))))

  (testing "Signed token unathorized request 3"
    (let [signed-data     (s/dumps {:userid 1} "wrong-key")
          header-content  (format "Token %s" signed-data)
          request         {:headers {"authorization" header-content}}
          uhandler        (fn [_ _] {:status 3000})
          backend         (stoken/signed-token-backend {:privkey secret-key
                                                        :unauthorized-handler uhandler})
          handler         (-> (fn [req] (throw-unauthorized))
                              (wrap-authorization backend)
                              (wrap-authentication backend))
          resp            (handler request)]
      (is (= (:status resp) 3000))))

    (testing "Basic token backend authentication 01"
      (let [request              {:headers {"authorization" "Token token1"}}
            backend              (stoken/token-backend {:authfn authfn})
            handler              (-> (fn [request] (:identity request))
                                     (wrap-authentication backend))
            response             (handler request)]
        (is (= response {:userid 1}))))

    (testing "Token backend with unauthorized requests 1"
      (let [request  {:headers {"authorization" "Token token1"}}
            backend  (stoken/token-backend {:authfn authfn})
            handler  (-> (fn [request] (throw-unauthorized))
                         (wrap-authorization backend)
                         (wrap-authentication backend))
            response (handler request)]
        (is (= (:status response) 403))))

    (testing "Token backend with unauthorized requests 2"
      (let [request  {:headers {"authorization" "Token token3"}}
            backend  (stoken/token-backend {:authfn authfn})
            handler  (-> (fn [request] (throw-unauthorized))
                         (wrap-authorization backend)
                         (wrap-authentication backend))
            response (handler request)]
        (is (= (:status response) 401))))

    (testing "Token backend with unauthorized requests 3"
      (let [request  {:headers {"authorization" "Token token3"}}
            uhandler (fn [_ _] {:status 3000})
            backend  (stoken/token-backend {:authfn authfn
                                            :unauthorized-handler uhandler})
            handler  (-> (fn [request] (throw-unauthorized))
                         (wrap-authorization backend)
                         (wrap-authentication backend))
            response (handler request)]
        (is (= (:status response) 3000))))

))

(deftest session-auth-test
  (testing "Simple backend authentication 01"
    (let [request {:session {:identity {:userid 1}}}
          backend (session-backend)
          handler (fn [req] req)
          handler (wrap-authentication handler backend)
          resp    (handler request)]
      (is (= (:identity resp) {:userid 1}))))

  (testing "Simple backend authentication 02"
    (let [request {:session {}}
          backend (session-backend)
          handler (fn [req] )
          handler (wrap-authentication handler backend)
          resp    (handler request)]
      (is (nil? (:identity resp)))))

  (testing "Handle unauthenticated unauthorized requests without specifying unauthorized handler"
    (let [request {:session {}}
          backend (session-backend)
          handler (-> (fn [req] (throw-unauthorized "FooMsg"))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          resp    (handler request)]
      (is (= (:status resp) 401))))

  (testing "Handle unauthorized requests specifying unauthorized handler"
    (let [request {:session {}}
          uhander (fn [request metadata] {:body "" :status 3000})
          backend (session-backend {:unauthorized-handler uhander})
          handler (-> (fn [req] (throw-unauthorized "FooMsg"))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          resp    (handler request)]
      (is (= (:status resp) 3000))))

  (testing "Handle authenticated unauthorized requests without specifying unauthorized handler"
    (let [request {:session {:identity {:userid 1}}}
          backend (session-backend)
          handler (-> (fn [req] (throw-unauthorized "FooMsg"))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          resp    (handler request)]
      (is (= (:status resp) 403)))))

(deftest authentication-middleware-test-with-httpbasic
  (testing "Auth middleware with http-basic backend 01"
    (let [backend (http-basic-backend {:realm "Foo"})
          handler (fn [req] req)
          handler (wrap-authentication handler backend)
          req     (make-httpbasic-request "user" "pass")
          resp    (handler req)]
        (is (nil? (:identity resp)))))

  (testing "Auth middleware with http-basic backend 02"
    (let [backend (http-basic-backend {:realm "Foo" :authfn httpbasic-auth-fn})
          handler (fn [req] req)
          handler (wrap-authentication handler backend)]
      (let [req   (make-httpbasic-request "user" "pass")
            resp  (handler req)]
        (is (nil? (:identity resp))))
      (let [req   (make-httpbasic-request "foo" "pass")
            resp  (handler req)]
        (is (= (:identity resp) :foo))))))

(deftest authorization-middleware-test-with-httpbasic
  (testing "Authorization middleware tests 01 with httpbasic backend"
    (let [backend (http-basic-backend {:realm "Foo" :authfn httpbasic-auth-fn})
          handler (fn [req] (if (nil? (:identity req))
                              (throw-unauthorized {:msg "FooMsg"})
                              req))
          handler (wrap-authorization handler backend)
          handler (wrap-authentication handler backend)
          req     (make-httpbasic-request "user" "pass")
          resp    (handler req)]
      (is (= (:status resp) 401))))
  (testing "Authorization middleware tests 02 with httpbasic backend"
    (let [backend (http-basic-backend {:realm "Foo" :authfn httpbasic-auth-fn})
          handler (fn [req] (if (nil? (:identity req))
                              (throw-unauthorized {:msg "FooMsg"})
                              req))
          handler (wrap-authorization handler backend)
          handler (wrap-authentication handler backend)
          req     (make-httpbasic-request "foo" "pass")
          resp    (handler req)]
      (is (= (:identity resp) :foo))))
  (testing "Authorization middleware tests 03 with httpbasic backend"
    (let [backend (http-basic-backend {:realm "Foo" :authfn httpbasic-auth-fn})
          handler (fn [req] (throw-unauthorized {:msg "FooMsg"}))
          handler (wrap-authorization handler backend)
          handler (wrap-authentication handler backend)
          req     (make-httpbasic-request "foo" "pass")
          resp    (handler req)]
      (is (= (:status resp) 403)))))

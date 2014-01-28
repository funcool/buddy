(ns sessionexample.core
  (:require [compojure.route :as route]
            [compojure.core :refer :all]
            [compojure.response :refer [render]]
            [clojure.java.io :as io]
            [ring.util.response :refer [response redirect content-type]]
            [ring.middleware.session :refer [wrap-session]]
            [ring.middleware.params :refer [wrap-params]]
            [ring.adapter.jetty :as jetty]
            [buddy.auth :refer [authenticated? throw-notauthorized]]
            [buddy.auth.backends.session :refer [session-backend]]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]])
  (:gen-class))

;; This macro works as decorator

(defmacro authentication-required
  [handler]
  `(fn [request#]
     (if (authenticated? request#)
       (~handler request#)
       (throw-notauthorized {:msg "Valid user is required"}))))

;; Views

(defn home-view
  [request]
  (response (slurp (io/resource "index.html"))))

(defn login-view
  [t request]
  (if (= t :get)
    (render (slurp (io/resource "login.html")) request)
    (let [username  (get (:form-params request) "username")
          session   (assoc (:session request) :identity (keyword username))]
      (-> (redirect (get (:query-params request) :next "/"))
          (assoc :session session)))))

(defn logout-view
  [request]
  (-> (redirect "/login")
      (assoc :session {})))

;; Routes

(defroutes app
  (GET "/" [] (authentication-required home-view))
  (GET "/login" [] (partial login-view :get))
  (POST "/login" [] (partial login-view :post))
  (GET "/logout" [] logout-view))

;; Self defined unauthorized handler

(defn unauthorized-handler
  [request metadata]
  (if (authenticated? request)
    (render (slurp (io/resource "error.html")) request)
    (let [current-url (:uri request)]
      (redirect (format "/login?next=%s" current-url)))))

(defn -main
  [& args]
  (let [backend (session-backend :unauthorized-handler unauthorized-handler)
        handler (-> app
                    (wrap-params)
                    (wrap-authorization backend)
                    (wrap-authentication backend)
                    (wrap-session))]
    (println "Now listening on: http://127.0.0.1:9090/")
    (jetty/run-jetty handler {:port 9090})))

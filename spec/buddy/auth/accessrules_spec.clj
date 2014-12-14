(ns buddy.auth.accessrules-spec
  (:require [speclj.core :refer :all]
            [ring.util.response :as ring]
            [cats.core :as m]
            [cats.monad.either :as either]
            [buddy.auth.accessrules :refer [compile-rule-handler restrict wrap-access-rules
                                            success error]]))

(defn ok [v] (success v))
(defn fail [v] (error v))

(defn ok2 [v] true)
(defn fail2 [v] false)

(describe "Compile one rule (handler or composition of them)"
  (it "compile access rules 1"
    (let [rule (compile-rule-handler ok)
          result (rule 1)]
      (should= (success 1) result)))

  (it "compile access rules 2"
    (let [rule (compile-rule-handler {:or [ok fail]})
          result (rule 1)]
      (should= (success 1) result)))

  (it "compile access rules 3"
    (let [rule (compile-rule-handler {:and [ok fail]})
          result (rule 1)]
      (should= (error 1) result)))

  (it "compile access rules 4"
    (let [rule (compile-rule-handler {:or [fail fail {:and [ok ok]}]})
          result (rule 1)]
      (should= (success 1) result)))

  (it "compile access rules 5"
    (let [rule (compile-rule-handler {:and [ok ok]})
          result (rule 1)]
      (should= (success 1) result)))

  (it "compile access rules 6"
    (let [rule (compile-rule-handler {:and [ok2 ok2]})
          result (rule 1)]
      (should= true result)))

  (it "compile access rules 7"
    (let [rule (compile-rule-handler {:or [fail2 ok2]})
          result (rule 1)]
      (should= true result)))
)

(defn test-handler
  [req]
  (ring/response req))

(describe "Restrict one handler with ok"
  (it "restrict handler 1"
    (let [handler (restrict test-handler {:handler {:or [ok fail]}})
          rsp     (handler "test")]
      (should= "test" (:body rsp))))

  (it "restrict handler with failure 1"
    (let [handler (restrict test-handler {:handler {:or [fail fail]}})]
      (should-throw (handler 1))))

  (it "restrict handler with failure 2"
    (let [handler (restrict test-handler {:handler {:or [fail fail]}})
          rsp (handler "Failure message")]
      (should= "Failure message" (:body rsp))
      (should= 400 (:status rsp))))

  (it "restrict handlerw with failure and explicit on-error handler"
    (let [handler (restrict test-handler
                            {:handler {:or [fail fail]}
                             :on-error (fn [req val] (ring/response (str "onfail-" val)))})
          rsp     (handler "test")]
      (should= "onfail-test" (:body rsp))))

  (it "restrict handlerw with failure and redirect"
    (let [handler (restrict test-handler
                            {:handler {:or [fail fail]}
                             :redirect "/foobar"})
          rsp     (handler "test")]
      (should= 302 (:status rsp))
      (should= "/foobar" (get-in rsp [:headers "Location"]))))
)



(def params1
  {:rules [{:pattern #"^/path1$"
            :handler {:or [ok fail]}}
           {:pattern #"^/path2$"
            :handler ok}
           {:pattern #"^/path3$"
            :handler {:and [fail ok]}}]})

(def params2
  {:rules [{:uri "/path1"
            :handler {:or [ok fail]}}
           {:uri "/path2"
            :handler ok}
           {:uri "/path3"
            :handler {:and [fail ok]}}]})

(defn on-error
  [req val]
  (-> (ring/response val)
      (ring/status 400)))


(def handler1
  (wrap-access-rules test-handler
                     (assoc params1 :policy :reject)))

(def handler2
  (wrap-access-rules test-handler
                     (assoc params1
                       :policy :reject
                       :on-error on-error)))

(def handler3
  (wrap-access-rules test-handler
                     (assoc params2 :policy :reject)))

(describe "Wrap access rules using pattern"
  (it "check access rules 1"
    (let [rsp (handler1 {:uri "/path1"})]
      (should= {:uri "/path1"} (:body rsp))))

  (it "check access rules 2"
    (let [rsp (handler1 {:uri "/path2"})]
      (should= {:uri "/path2"} (:body rsp))))

  (it "check access rules 3"
    (should-throw (handler1 {:uri "/path3"})))

  (it "check access rules 4"
    (should-throw (handler1 {:uri "/path4"})))

  (it "check access rules 5"
    (let [rsp (handler2 {:uri "/path3"})]
      (should= 400 (:status rsp))
      (should= {:uri "/path3"} (:body rsp))))

  (it "check access rules 6"
    (let [rsp (handler2 {:uri "/path4"})]
      (should= 400 (:status rsp))
      (should= nil (:body rsp))))
)

(describe "Wrap access rules using clout"
  (it "check access rules 1"
    (let [rsp (handler3 {:uri "/path1"})]
      (should= {:uri "/path1"} (:body rsp))))

  (it "check access rules 2"
    (let [rsp (handler3 {:uri "/path2"})]
      (should= {:uri "/path2"} (:body rsp))))

  (it "check access rules 3"
    (should-throw (handler3 {:uri "/path3"})))

  (it "check access rules 4"
    (should-throw (handler3 {:uri "/path4"})))
)

(run-specs)


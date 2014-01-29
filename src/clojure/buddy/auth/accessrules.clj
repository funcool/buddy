(ns buddy.auth.accessrules)

(defn compile-rule
  "Receives a rule handler and return one callable that
  can return true or false.
  The handler can be a simple symbol:

    my-function

  Or logicaly combined hash-map:

    {:or [my-func1 my-func2]}
    {:and [my-func1 my-func2]}

  Also, logic combinators can be nested:

    {:or [my-func1 {:and [myfn3 myfn4]}]}

  Note: The theorycaly limit of nesting is a recursion
  stack of clojure/java."
  [handler]
  (if (map? handler)
    (cond
      (:or handler) (fn [req]
                      (->> (map compile-rule (:or handler))
                           (map (fn [h] (boolean (h req))))
                           (some true?)
                           (boolean)))
      (:and handler) (fn [req]
                       (->> (map compile-rule (:and handler))
                            (map (fn [h] (boolean (h req))))
                            (every? true?)
                            (boolean)))
      :else (throw (RuntimeException. "Invalid rule format")))
    (fn [req] (boolean (handler req)))))

(defn match-rules
  "Iterates over all rules and try match each one
  in order. Return a first matched rule or nil.
  This function is used by RegexAccessRules class."
  [request rules]
  (let [filterfn (fn [rule] (seq (re-matches (:pattern rule) (:uri request))))]
    (first (filter filterfn rules))))

(defn apply-rule
  [request rule]
  "Compiles a rule and execute the rule handlers tree.
  If result a boolean value: true for grant access and
  false for deny."
  (let [rulehandler (compile-rule ((:handler rule)))]
    (rulehandler request)))

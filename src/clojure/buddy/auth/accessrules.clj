(ns buddy.auth.accessrules)

(defmacro f-or [opts] `(or ~@opts))
(defmacro f-and [opts] `(and ~@opts))

(defn compile-rule
  "Receives a rule handler and return one callable that
  can return true or false."
  [handler]
  (if (map? handler)
    (cond
      (:or handler) (fn [req] (f-or (map (fn [h] (h req)) (map compile-rule (:or handler)))))
      (:and handler) (fn [req] (f-and (map (fn [h] (h req)) (map compile-rule (:and handler)))))
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

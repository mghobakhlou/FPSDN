open Base

type test = { var: string; value: bool } [@@deriving sexp]
type act = test

let sexp_of_act (a : act) = sexp_of_test a
let act_of_sexp (s : Sexp.t) = test_of_sexp s

type bexp = test Kat.Ast.bexp [@@deriving sexp]
type exp = (act, test) Kat.Ast.exp [@@deriving sexp]
import unittest

from duckysandbox.parser import parse


class TestParser(unittest.TestCase):
    def test_string_and_stringln(self):
        program = parse("STRING hello\nSTRINGLN world\n")
        ops = [i.op for i in program.instructions]
        self.assertEqual(ops, ["STRING", "STRINGLN"])
        self.assertEqual(program.instructions[0].arg, "hello")
        self.assertEqual(program.instructions[1].arg, "world")

    def test_key_chord(self):
        program = parse("GUI r\nCTRL ALT DELETE\n")
        first, second = program.instructions
        self.assertEqual(first.op, "KEY")
        self.assertEqual(first.keys, ["GUI", "r"])
        self.assertEqual(second.op, "KEY")
        self.assertEqual(second.keys, ["CTRL", "ALT", "DELETE"])

    def test_delay_variants(self):
        program = parse("DELAY 500\nDEFAULT_DELAY 100\nSTRING_DELAY 10\n")
        ops = [(i.op, i.arg) for i in program.instructions]
        self.assertEqual(ops, [("DELAY", "500"), ("DEFAULT_DELAY", "100"), ("CHAR_DELAY", "10")])

    def test_comments_ignored_for_structure(self):
        program = parse("REM hello\nSTRING test\n")
        self.assertEqual([i.op for i in program.instructions], ["REM", "STRING"])

    def test_if_else_end_if_structure(self):
        text = "\n".join([
            "IF (1 == 1) THEN",
            "STRING a",
            "ELSE_IF (2 == 2) THEN",
            "STRING b",
            "ELSE",
            "STRING c",
            "END_IF",
        ])
        program = parse(text)
        ins = program.instructions
        if_idx = next(i for i, x in enumerate(ins) if x.op == "IF")
        elseif_idx = next(i for i, x in enumerate(ins) if x.op == "ELSE_IF")
        else_idx = next(i for i, x in enumerate(ins) if x.op == "ELSE")
        endif_idx = next(i for i, x in enumerate(ins) if x.op == "END_IF")

        self.assertEqual(program.branch_next[if_idx], elseif_idx)
        self.assertEqual(program.branch_next[elseif_idx], else_idx)
        self.assertEqual(program.branch_next[else_idx], endif_idx)
        for h in (if_idx, elseif_idx, else_idx):
            self.assertEqual(program.branch_end[h], endif_idx)
        self.assertEqual(program.instructions[if_idx].arg, "1 == 1")

    def test_while_end_while_structure(self):
        text = "WHILE (1 == 1)\nSTRING x\nEND_WHILE\n"
        program = parse(text)
        ins = program.instructions
        while_idx = next(i for i, x in enumerate(ins) if x.op == "WHILE")
        end_while_idx = next(i for i, x in enumerate(ins) if x.op == "END_WHILE")
        self.assertEqual(program.while_end[while_idx], end_while_idx)
        self.assertEqual(program.while_back[end_while_idx], while_idx)

    def test_function_definition_and_bare_call(self):
        text = "\n".join([
            "FUNCTION DoThing()",
            "STRING inside",
            "END_FUNCTION",
            "DoThing()",
        ])
        program = parse(text)
        self.assertIn("DOTHING", program.func_range)
        call_instr = program.instructions[-1]
        self.assertEqual(call_instr.op, "CALL")
        self.assertEqual(call_instr.arg, "DOTHING")

    def test_explicit_call_keyword(self):
        text = "\n".join([
            "FUNCTION DoThing()",
            "STRING inside",
            "END_FUNCTION",
            "CALL DoThing",
        ])
        program = parse(text)
        call_instr = program.instructions[-1]
        self.assertEqual(call_instr.op, "CALL")
        self.assertEqual(call_instr.arg, "DOTHING")

    def test_unbalanced_if_produces_warning(self):
        program = parse("IF (1 == 1) THEN\nSTRING a\n")
        self.assertTrue(any("END_IF" in w for w in program.warnings))

    def test_quack_prefix_unwrapped(self):
        program = parse("Q STRING hello\nQUACK ENTER\n")
        self.assertEqual(program.instructions[0].op, "STRING")
        self.assertEqual(program.instructions[0].arg, "hello")
        self.assertEqual(program.instructions[1].op, "KEY")

    def test_unknown_instruction(self):
        program = parse("THIS_IS_NOT_A_REAL_COMMAND foo\n")
        self.assertEqual(program.instructions[0].op, "UNKNOWN")

    def test_repeat_and_var(self):
        program = parse("STRING A\nREPEAT 4\nVAR $x = 5\n")
        ops = [i.op for i in program.instructions]
        self.assertEqual(ops, ["STRING", "REPEAT", "VAR"])
        self.assertEqual(program.instructions[1].arg, "4")
        self.assertEqual(program.instructions[2].arg, "$x = 5")


if __name__ == "__main__":
    unittest.main()

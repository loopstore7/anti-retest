import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date, datetime, timedelta, timezone
from io import StringIO
from pathlib import Path

from antiretest import (
    MARK_EXPIRED,
    MARK_INVALID,
    MARK_KNOWN,
    MARK_NEW,
    AntiRetest,
    DailyLog,
    InvalidNumberError,
    default_log_dir,
    is_fingerprint_line,
    mask,
    mask_vulgo,
    normalize,
    parse_entry,
)
from antiretest.cli import main

VALID = "4111111111111111"
OTHER = "5555555555554444"
AMEX = "371449635398431"

# A entrada agora exige a linha completa: PAN, validade e CVV.
LINHA = f"{VALID}|12|2028|123"
OUTRA = f"{OTHER}|03|2029|456"
AMEX_LINHA = f"{AMEX}|07|2030|1234"
VENCIDA = f"{VALID}|01|2020|123"

BASE = datetime(2026, 1, 10, 12, 0, tzinfo=timezone.utc)


def dia(momento: datetime) -> date:
    """Dia do txt: o log corta o dia no fuso local, o banco corta em UTC."""
    return momento.astimezone().date()


class ParseEntryTest(unittest.TestCase):
    def test_reads_pan_expiry_and_cvv(self):
        entrada = parse_entry(LINHA)
        self.assertEqual(entrada.pan, VALID)
        self.assertEqual(entrada.month, 12)
        self.assertEqual(entrada.year, 2028)
        self.assertEqual(entrada.cvv, "123")

    def test_two_digit_year_becomes_four(self):
        self.assertEqual(parse_entry(f"{VALID}|10|29|729").year, 2029)

    def test_accepts_noise_around_the_fields(self):
        entrada = parse_entry(f"Reprovada {VALID}|10|29|729 - Refused")
        self.assertEqual(entrada.pan, VALID)
        self.assertEqual(entrada.cvv, "729")

    def test_accepts_other_separators_and_formatting(self):
        self.assertEqual(parse_entry("4111 1111-1111.1111 / 12 / 28 / 123").pan, VALID)
        self.assertEqual(parse_entry(f"{VALID};12;2028;123").pan, VALID)

    def test_accepts_everything_glued_together(self):
        self.assertEqual(parse_entry("4111 1111 1111 1111 12 2028 123").pan, VALID)
        self.assertEqual(parse_entry(f"{VALID}122028123").month, 12)

    def test_accepts_expiry_in_a_single_field(self):
        self.assertEqual(parse_entry(f"{VALID}|1228|123").year, 2028)

    def test_pan_does_not_need_to_come_first(self):
        self.assertEqual(parse_entry(f"12|2028|{VALID}|123").pan, VALID)

    def test_rejects_pan_alone(self):
        with self.assertRaises(InvalidNumberError):
            parse_entry(VALID)

    def test_rejects_pan_without_cvv(self):
        with self.assertRaises(InvalidNumberError):
            parse_entry(f"{VALID}|12|2028")

    def test_rejects_pan_without_expiry(self):
        with self.assertRaises(InvalidNumberError):
            parse_entry(f"{VALID}|123")

    def test_rejects_month_out_of_range(self):
        with self.assertRaises(InvalidNumberError):
            parse_entry(f"{VALID}|13|2028|123")

    def test_rejects_cvv_of_two_digits(self):
        with self.assertRaises(InvalidNumberError):
            parse_entry(f"{VALID}|12|2028|12")

    def test_message_says_what_is_missing(self):
        with self.assertRaises(InvalidNumberError) as erro:
            parse_entry(VALID)
        self.assertIn("PAN|MM|AAAA|CVV", str(erro.exception))


class AmexTest(unittest.TestCase):
    def test_accepts_fifteen_digits_with_four_digit_cvv(self):
        entrada = parse_entry(AMEX_LINHA)
        self.assertEqual(entrada.pan, AMEX)
        self.assertTrue(entrada.is_amex)
        self.assertEqual(entrada.cvv, "1234")

    def test_rejects_amex_with_three_digit_cvv(self):
        with self.assertRaises(InvalidNumberError):
            parse_entry(f"{AMEX}|07|2030|123")

    def test_rejects_four_digit_cvv_on_other_brands(self):
        with self.assertRaises(InvalidNumberError):
            parse_entry(f"{VALID}|12|2028|1234")

    def test_rejects_fifteen_digits_that_are_not_amex(self):
        with self.assertRaises(InvalidNumberError):
            parse_entry("411111111111111|12|2028|1234")

    def test_mask_has_the_same_length_as_the_pan(self):
        self.assertEqual(mask(AMEX), "371449*****8431")
        self.assertEqual(len(mask(AMEX)), 15)


class ExpiryTest(unittest.TestCase):
    def test_past_expiry_is_expired(self):
        self.assertTrue(parse_entry(VENCIDA).is_expired(date(2026, 1, 10)))

    def test_current_month_is_not_expired(self):
        self.assertFalse(parse_entry(f"{VALID}|01|2026|123").is_expired(date(2026, 1, 31)))

    def test_future_expiry_is_not_expired(self):
        self.assertFalse(parse_entry(LINHA).is_expired(date(2026, 1, 10)))


class NormalizeTest(unittest.TestCase):
    """normalize continua aceitando só o PAN: é o caminho de forget e verify."""

    def test_accepts_separators(self):
        self.assertEqual(normalize("4111 1111-1111.1111"), VALID)

    def test_ignores_expiry_and_cvv_fields(self):
        self.assertEqual(normalize(LINHA), VALID)

    def test_finds_pan_when_it_is_not_the_first_field(self):
        self.assertEqual(normalize(f"12|2028|{VALID}|123"), VALID)

    def test_accepts_amex(self):
        self.assertEqual(normalize(AMEX_LINHA), AMEX)

    def test_rejects_line_without_valid_pan(self):
        with self.assertRaises(InvalidNumberError):
            normalize("4111111111111112|12|2028|123")

    def test_rejects_wrong_length(self):
        with self.assertRaises(InvalidNumberError):
            normalize("411111111111111")

    def test_rejects_bad_luhn(self):
        with self.assertRaises(InvalidNumberError):
            normalize("4111111111111112")

    def test_rejects_letters(self):
        with self.assertRaises(InvalidNumberError):
            normalize("4111a11111111111")

    def test_mask_keeps_bin_and_last4(self):
        self.assertEqual(mask(VALID), "411111******1111")


class MaskVulgoTest(unittest.TestCase):
    def test_masks_store_name(self):
        self.assertEqual(mask_vulgo("CcStore"), "CcS****")

    def test_sexta_style_mask(self):
        self.assertEqual(mask_vulgo("Sexta"), "Sex**")

    def test_short_names(self):
        self.assertEqual(mask_vulgo("Ab"), "A*")
        self.assertEqual(mask_vulgo("Abcd"), "Abc*")
        self.assertEqual(mask_vulgo("Sex"), "Sex")

    def test_empty_returns_empty(self):
        self.assertEqual(mask_vulgo(""), "")
        self.assertEqual(mask_vulgo("   "), "")


class FingerprintLineTest(unittest.TestCase):
    def test_accepts_64_hex(self):
        fp = "a" * 64
        self.assertTrue(is_fingerprint_line(fp))
        self.assertTrue(is_fingerprint_line(fp.upper()))

    def test_rejects_invalid(self):
        self.assertFalse(is_fingerprint_line("abc"))
        self.assertFalse(is_fingerprint_line("g" * 64))


class AntiRetestTest(unittest.TestCase):
    def setUp(self):
        self.engine = AntiRetest(":memory:", key=b"test-key")
        self.addCleanup(self.engine.close)

    def test_first_check_is_new(self):
        result = self.engine.check(LINHA, now=BASE)
        self.assertFalse(result.is_retest)
        self.assertEqual(result.status, "new")
        self.assertEqual(result.added_on, BASE.date())
        self.assertEqual(result.attempts, 1)
        self.assertEqual(result.expiry, "12/2028")
        self.assertFalse(result.expired)

    def test_incomplete_line_is_refused(self):
        with self.assertRaises(InvalidNumberError):
            self.engine.check(VALID, now=BASE)
        with self.assertRaises(InvalidNumberError):
            self.engine.check(f"{VALID}|12|2028", now=BASE)
        self.assertEqual(self.engine.stats()["total"], 0)

    def test_expired_card_is_accepted_and_flagged(self):
        result = self.engine.check(VENCIDA, now=BASE)
        self.assertTrue(result.expired)
        self.assertIn("VENCIDO", result.describe())

    def test_amex_is_stored_with_its_own_length(self):
        result = self.engine.check(AMEX_LINHA, now=BASE)
        self.assertEqual(result.masked, mask(AMEX))
        self.assertEqual(self.engine.recent()[0]["masked"], mask(AMEX))

    def test_known_number_keeps_original_date(self):
        self.engine.check(LINHA, now=BASE)
        result = self.engine.check(LINHA, now=BASE + timedelta(days=5))
        self.assertTrue(result.is_retest)
        self.assertEqual(result.status, "known")
        self.assertEqual(result.added_on, BASE.date())
        self.assertEqual(result.days_since_added, 5)
        self.assertEqual(result.attempts, 2)

    def test_vulgo_is_stored_on_new_and_shown_on_retest(self):
        novo = self.engine.check(LINHA, now=BASE, vulgo="Cliente X")
        self.assertEqual(novo.vulgo, "Cliente X")
        repetido = self.engine.check(LINHA, now=BASE + timedelta(days=1), vulgo="Outro")
        self.assertTrue(repetido.is_retest)
        self.assertEqual(repetido.vulgo, "Cliente X")

    def test_retest_describe_shows_masked_vulgo(self):
        self.engine.check(LINHA, now=BASE, vulgo="CcStore")
        repetido = self.engine.check(LINHA, now=BASE + timedelta(days=1), vulgo="Outro")
        self.assertIn("Testado por: CcS****", repetido.describe())

    def test_check_by_fingerprint_finds_existing(self):
        novo = self.engine.check(LINHA, now=BASE, vulgo="LojaTeste")
        resultado = self.engine.check_by_fingerprint(novo.fingerprint, now=BASE + timedelta(days=2))
        self.assertTrue(resultado.is_retest)
        self.assertEqual(resultado.vulgo, "LojaTeste")
        self.assertEqual(resultado.attempts, 2)

    def test_check_by_fingerprint_rejects_unknown(self):
        with self.assertRaises(InvalidNumberError):
            self.engine.check_by_fingerprint("a" * 64, now=BASE)

    def test_known_after_years_is_still_known(self):
        self.engine.check(LINHA, now=BASE)
        result = self.engine.check(LINHA, now=BASE + timedelta(days=1500))
        self.assertTrue(result.is_retest)
        self.assertEqual(result.status, "known")
        self.assertEqual(result.days_since_added, 1500)
        self.assertEqual(result.added_on, BASE.date())

    def test_formatting_variants_hit_same_record(self):
        self.engine.check("4111-1111-1111-1111|12|2028|123", now=BASE)
        result = self.engine.check(
            "4111 1111 1111 1111 / 12 / 2028 / 123", now=BASE + timedelta(days=1)
        )
        self.assertTrue(result.is_retest)
        self.assertEqual(result.attempts, 2)

    def test_same_pan_with_different_extras_hits_same_record(self):
        self.engine.check(LINHA, now=BASE)
        result = self.engine.check(
            "4111 1111 1111 1111|05|2031|999", now=BASE + timedelta(days=3)
        )
        self.assertTrue(result.is_retest)
        self.assertEqual(result.attempts, 2)
        self.assertEqual(result.added_on, BASE.date())

    def test_cc_full_holds_line_not_fingerprint(self):
        result = self.engine.check(LINHA, now=BASE)
        row = self.engine._conn.execute(
            "SELECT fingerprint, cc_full FROM entries WHERE fingerprint = ?",
            (result.fingerprint,),
        ).fetchone()
        self.assertEqual(row["cc_full"], LINHA)
        self.assertNotIn(VALID, row["fingerprint"])

    def test_distinct_numbers_are_independent(self):
        self.engine.check(LINHA, now=BASE)
        result = self.engine.check(OUTRA, now=BASE)
        self.assertFalse(result.is_retest)

    def test_dry_run_does_not_record(self):
        self.engine.check(LINHA, now=BASE, record=False)
        result = self.engine.check(LINHA, now=BASE)
        self.assertFalse(result.is_retest)

    def test_dry_run_keeps_attempt_count(self):
        self.engine.check(LINHA, now=BASE)
        peek = self.engine.check(LINHA, now=BASE + timedelta(days=2), record=False)
        self.assertEqual(peek.attempts, 1)
        again = self.engine.check(LINHA, now=BASE + timedelta(days=2))
        self.assertEqual(again.attempts, 2)

    def test_forget_accepts_the_pan_alone(self):
        self.engine.check(LINHA, now=BASE)
        self.assertTrue(self.engine.forget(VALID))
        self.assertFalse(self.engine.forget(VALID))
        self.assertFalse(self.engine.check(LINHA, now=BASE).is_retest)

    def test_purge_drops_only_old_records(self):
        self.engine.check(LINHA, now=BASE)
        self.engine.check(OUTRA, now=BASE + timedelta(days=40))
        removed = self.engine.purge(30, now=BASE + timedelta(days=45))
        self.assertEqual(removed, 1)
        self.assertFalse(self.engine.check(LINHA, now=BASE + timedelta(days=45)).is_retest)
        self.assertTrue(self.engine.check(OUTRA, now=BASE + timedelta(days=45)).is_retest)

    def test_stats(self):
        self.engine.check(LINHA, now=BASE)
        self.engine.check(LINHA, now=BASE + timedelta(days=1))
        self.engine.check(OUTRA, now=BASE + timedelta(days=2))
        stats = self.engine.stats()
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["attempts"], 3)
        self.assertEqual(stats["repetidos"], 1)
        self.assertEqual(stats["retested"], 1)
        self.assertEqual(stats["first_day"], BASE.date().isoformat())

    def test_verify_matches_fingerprint(self):
        result = self.engine.check(LINHA, now=BASE)
        self.assertTrue(self.engine.verify(VALID, result.fingerprint))
        self.assertFalse(self.engine.verify(OTHER, result.fingerprint))

    def test_cc_full_is_stored(self):
        result = self.engine.check(LINHA, now=BASE)
        self.assertEqual(result.cc_full, f"{VALID}|12|2028|123")
        row = self.engine._conn.execute(
            "SELECT cc_full FROM entries WHERE fingerprint = ?", (result.fingerprint,)
        ).fetchone()
        self.assertEqual(row["cc_full"], f"{VALID}|12|2028|123")

    def test_import_file_loads_reprovada_lines(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write(f"Reprovada {VALID}|10|29|729 - Refused\n")
            handle.write(f"{LINHA}\n")
            handle.write("lixo sem número\n")
            path = handle.name

        result = self.engine.import_file(path, now=BASE)
        self.assertEqual(result["lines"], 3)
        self.assertEqual(result["imported"], 1)
        self.assertEqual(result["duplicates"], 1)
        self.assertEqual(result["invalid"], 1)
        self.assertTrue(self.engine.check(LINHA, now=BASE + timedelta(days=1)).is_retest)

    def test_import_refuses_lines_without_expiry_or_cvv(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write(f"{VALID}\n{VALID}|12|2028\n{LINHA}\n")
            path = handle.name

        result = self.engine.import_file(path, now=BASE)
        self.assertEqual(result["invalid"], 2)
        self.assertEqual(result["imported"], 1)

    def test_import_counts_expired_cards(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write(f"{VENCIDA}\n{OUTRA}\n")
            path = handle.name

        result = self.engine.import_file(path, now=BASE)
        self.assertEqual(result["imported"], 2)
        self.assertEqual(result["expired"], 1)

    def test_import_file_skips_existing_records(self):
        self.engine.check(LINHA, now=BASE)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write(f"{LINHA}\n")
            path = handle.name

        result = self.engine.import_file(path, now=BASE)
        self.assertEqual(result["imported"], 0)
        self.assertEqual(result["duplicates"], 1)


class DailyLogTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.pasta = Path(tmp.name) / "registros"
        self.log = DailyLog(self.pasta)

    def test_file_is_named_after_the_local_day(self):
        path = self.log.append(LINHA, MARK_NEW, now=BASE)
        self.assertEqual(path.name, f"{dia(BASE).isoformat()}.txt")
        self.assertEqual(path.read_text(encoding="utf-8"), f"{LINHA}|{MARK_NEW}\n")

    def test_day_turns_at_local_midnight(self):
        local = BASE.astimezone()
        antes = local.replace(hour=23, minute=50)
        depois = antes + timedelta(minutes=20)
        self.log.append(LINHA, MARK_NEW, now=antes)
        self.log.append(OUTRA, MARK_NEW, now=depois)
        self.assertEqual(self.log.days(), [antes.date(), depois.date()])

    def test_one_file_per_day(self):
        outro = BASE + timedelta(days=1)
        self.log.append(LINHA, MARK_NEW, now=BASE)
        self.log.append(OUTRA, MARK_NEW, now=outro)
        self.assertEqual(self.log.days(), [dia(BASE), dia(outro)])
        self.assertEqual(self.log.numbers_for(dia(BASE)), [f"{LINHA}|{MARK_NEW}"])
        self.assertEqual(self.log.numbers_for(dia(outro)), [f"{OUTRA}|{MARK_NEW}"])

    def test_same_day_accumulates_in_order(self):
        self.log.append_many([(LINHA, MARK_NEW), (OUTRA, MARK_KNOWN)], now=BASE)
        self.assertEqual(
            self.log.entries_for(dia(BASE)),
            [(LINHA, (MARK_NEW,)), (OUTRA, (MARK_KNOWN,))],
        )
        self.assertEqual(self.log.counts(), [(dia(BASE), 2)])

    def test_two_marks_in_the_same_line(self):
        path = self.log.append(VENCIDA, MARK_NEW, MARK_EXPIRED, now=BASE)
        self.assertEqual(
            path.read_text(encoding="utf-8"), f"{VENCIDA}|{MARK_NEW}|{MARK_EXPIRED}\n"
        )
        self.assertEqual(
            self.log.entries_for(dia(BASE)), [(VENCIDA, (MARK_NEW, MARK_EXPIRED))]
        )

    def test_tally_counts_each_mark(self):
        self.log.append_many(
            [
                (LINHA, (MARK_NEW,)),
                (VENCIDA, (MARK_KNOWN, MARK_EXPIRED)),
                ("lixo", (MARK_INVALID,)),
            ],
            now=BASE,
        )
        resumo = self.log.tally(dia(BASE))
        self.assertEqual(resumo["total"], 3)
        self.assertEqual(resumo[MARK_NEW], 1)
        self.assertEqual(resumo[MARK_KNOWN], 1)
        self.assertEqual(resumo[MARK_INVALID], 1)
        self.assertEqual(resumo[MARK_EXPIRED], 1)

    def test_keeps_the_line_as_received(self):
        linha = f"Reprovada {VALID}|10|29|729 - Refused"
        self.log.append(linha, MARK_NEW, now=BASE)
        self.assertEqual(self.log.entries_for(dia(BASE)), [(linha, (MARK_NEW,))])

    def test_line_without_mark_is_read_back_whole(self):
        self.log.append(LINHA, now=BASE)
        self.assertEqual(self.log.entries_for(dia(BASE)), [(LINHA, ())])

    def test_entry_never_becomes_two_lines(self):
        self.log.append(f"{LINHA}\n{OUTRA}", MARK_NEW, now=BASE)
        self.assertEqual(
            self.log.entries_for(dia(BASE)), [(f"{LINHA} {OUTRA}", (MARK_NEW,))]
        )

    def test_blank_lines_create_nothing(self):
        self.log.append_many([("", MARK_NEW), ("   ", MARK_INVALID)], now=BASE)
        self.assertFalse(self.pasta.exists())

    def test_day_without_file_is_empty(self):
        self.assertEqual(self.log.days(), [])
        self.assertEqual(self.log.numbers_for(dia(BASE)), [])


class EngineDailyLogTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.pasta = Path(tmp.name) / "registros"
        self.engine = AntiRetest(":memory:", key=b"test-key", log_dir=self.pasta)
        self.addCleanup(self.engine.close)
        self.log = DailyLog(self.pasta)

    def test_disabled_without_log_dir(self):
        engine = AntiRetest(":memory:", key=b"test-key")
        self.addCleanup(engine.close)
        self.assertIsNone(engine._log)

    def test_new_line_is_written_to_the_day_file(self):
        self.engine.check("4111 1111-1111.1111|12|2028|123", now=BASE)
        self.assertEqual(
            self.log.entries_for(dia(BASE)),
            [("4111 1111-1111.1111|12|2028|123", (MARK_NEW,))],
        )

    def test_full_line_is_written(self):
        self.engine.check(LINHA, now=BASE)
        conteudo = self.log.path_for(dia(BASE)).read_text(encoding="utf-8")
        self.assertEqual(conteudo, f"{LINHA}|{MARK_NEW}\n")

    def test_expired_card_gets_two_marks(self):
        self.engine.check(VENCIDA, now=BASE)
        self.assertEqual(
            self.log.entries_for(dia(BASE)), [(VENCIDA, (MARK_NEW, MARK_EXPIRED))]
        )

    def test_txt_can_be_reimported(self):
        self.engine.check(VENCIDA, now=BASE)
        self.assertTrue(self.engine.forget(VALID))
        result = self.engine.import_file(self.log.path_for(dia(BASE)), now=BASE)
        self.assertEqual(result["imported"], 1)
        self.assertEqual(result["invalid"], 0)
        self.assertEqual(result["expired"], 1)

    def test_known_number_is_marked_as_repeated(self):
        outro = BASE + timedelta(days=1)
        self.engine.check(LINHA, now=BASE)
        self.engine.check(LINHA, now=outro)
        self.assertEqual(self.log.entries_for(dia(BASE)), [(LINHA, (MARK_NEW,))])
        self.assertEqual(self.log.entries_for(dia(outro)), [(LINHA, (MARK_KNOWN,))])

    def test_invalid_line_is_marked(self):
        with self.assertRaises(InvalidNumberError):
            self.engine.check("lixo sem número", now=BASE)
        with self.assertRaises(InvalidNumberError):
            self.engine.check(VALID, now=BASE)
        self.assertEqual(
            self.log.entries_for(dia(BASE)),
            [("lixo sem número", (MARK_INVALID,)), (VALID, (MARK_INVALID,))],
        )

    def test_dry_run_is_not_written(self):
        self.engine.check(LINHA, now=BASE, record=False)
        with self.assertRaises(InvalidNumberError):
            self.engine.check("4111", now=BASE, record=False)
        self.assertEqual(self.log.numbers_for(dia(BASE)), [])

    def test_import_marks_every_line(self):
        self.engine.check(OUTRA, now=BASE)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write(f"Reprovada {VALID}|10|29|729 - Refused\n")
            handle.write(f"{OUTRA}\n")
            handle.write("lixo sem número\n")
            handle.write(f"{VENCIDA}\n")
            path = handle.name

        result = self.engine.import_file(path, now=BASE)
        self.assertEqual(result["imported"], 1)
        self.assertEqual(
            self.log.entries_for(dia(BASE)),
            [
                (OUTRA, (MARK_NEW,)),
                (f"Reprovada {VALID}|10|29|729 - Refused", (MARK_NEW,)),
                (OUTRA, (MARK_KNOWN,)),
                ("lixo sem número", (MARK_INVALID,)),
                (VENCIDA, (MARK_KNOWN, MARK_EXPIRED)),
            ],
        )

    def test_import_drops_the_bom_of_the_first_line(self):
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8-sig", suffix=".txt", delete=False
        ) as handle:
            handle.write(f"{LINHA}\n")
            path = handle.name

        self.engine.import_file(path, now=BASE)
        self.assertEqual(self.log.entries_for(dia(BASE)), [(LINHA, (MARK_NEW,))])

    def test_import_keeps_counts_with_log_enabled(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write(f"{LINHA}\n{LINHA}\n{OUTRA}\n")
            path = handle.name

        result = self.engine.import_file(path, now=BASE)
        self.assertEqual(result["imported"], 2)
        self.assertEqual(result["duplicates"], 1)
        self.assertEqual(
            self.log.entries_for(dia(BASE)),
            [(LINHA, (MARK_NEW,)), (LINHA, (MARK_KNOWN,)), (OUTRA, (MARK_NEW,))],
        )


class CliTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = str(Path(tmp.name) / "cli.db")

    def _run(self, *argv):
        buffer = StringIO()
        with redirect_stdout(buffer):
            code = main(["--db", self.db, *argv])
        return code, buffer.getvalue()

    def test_new_then_known(self):
        code, out = self._run("check", LINHA)
        self.assertEqual(code, 0)
        self.assertIn("NOVO", out)

        code, out = self._run("check", LINHA)
        self.assertEqual(code, 1)
        self.assertIn("JÁ NO BANCO", out)

    def test_invalid_number_exits_two(self):
        code, _ = self._run("check", "1234")
        self.assertEqual(code, 2)

    def test_pan_alone_exits_two(self):
        erro = StringIO()
        with redirect_stderr(erro):
            code, _ = self._run("check", VALID)
        self.assertEqual(code, 2)
        self.assertIn("PAN|MM|AAAA|CVV", erro.getvalue())

    def test_json_output_masks_number(self):
        _, out = self._run("--json", "check", LINHA)
        payload = json.loads(out)
        self.assertEqual(payload[0]["status"], "new")
        self.assertEqual(payload[0]["masked"], mask(VALID))
        self.assertEqual(payload[0]["expiry"], "12/2028")
        self.assertFalse(payload[0]["expired"])
        self.assertNotIn(VALID, out)

    def test_cooldown_flag_is_gone(self):
        with self.assertRaises(SystemExit):
            with redirect_stdout(StringIO()):
                main(["--db", self.db, "--cooldown", "0", "check", LINHA])

    def test_forget_and_stats(self):
        self._run("check", LINHA)
        _, out = self._run("forget", VALID)
        self.assertIn("1 registro(s) removido(s)", out)
        _, out = self._run("stats")
        self.assertIn("total: 0", out)

    def test_import_command(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write(f"Reprovada {VALID}|10|29|729 - Refused\n")
            seed = handle.name

        code, out = self._run("import", seed)
        self.assertEqual(code, 0)
        self.assertIn("1 importado(s)", out)
        code, out = self._run("check", LINHA)
        self.assertEqual(code, 1)
        self.assertIn("JÁ NO BANCO", out)

    def test_check_writes_the_daily_txt(self):
        self._run("check", LINHA)
        self._run("check", LINHA)
        self._run("check", "4111")
        self.assertEqual(
            DailyLog(default_log_dir(self.db)).entries_for(dia(datetime.now(timezone.utc))),
            [(LINHA, (MARK_NEW,)), (LINHA, (MARK_KNOWN,)), ("4111", (MARK_INVALID,))],
        )

    def test_no_log_flag_writes_nothing(self):
        self._run("--no-log", "check", LINHA)
        self.assertFalse(default_log_dir(self.db).exists())

    def test_log_command_lists_days_and_lines(self):
        self._run("check", LINHA)
        self._run("check", VENCIDA)
        _, out = self._run("log")
        hoje = dia(datetime.now(timezone.utc)).isoformat()
        self.assertIn(f"{hoje}: 2 linha(s)", out)
        self.assertIn("1 novo(s), 1 repetido(s), 0 inválido(s), 1 vencido(s)", out)

        _, out = self._run("log", hoje)
        self.assertIn(f"{LINHA}|{MARK_NEW}", out)
        self.assertIn(f"{VENCIDA}|{MARK_KNOWN}|{MARK_EXPIRED}", out)

    def test_log_command_rejects_bad_date(self):
        code, _ = self._run("log", "10/01/2026")
        self.assertEqual(code, 2)


try:
    import tkinter

    from antiretest.gui import AntiRetestApp

    _TK = True
except Exception:  # pragma: no cover - ambiente sem Tk
    _TK = False


@unittest.skipUnless(_TK, "tkinter indisponível")
class GuiTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        try:
            self.root = tkinter.Tk()
        except tkinter.TclError as error:  # pragma: no cover - sem display
            self.skipTest(str(error))
        self.root.withdraw()
        self.addCleanup(self.root.destroy)
        self.app = AntiRetestApp(self.root, str(Path(tmp.name) / "gui.db"))

    def test_verificar_novo_e_conhecido(self):
        self.app.numero.set(LINHA)
        self.app.verificar()
        self.assertIn("NOVO", self.app.veredito.get())
        self.assertEqual(len(self.app.tabela.get_children()), 1)

        self.app.verificar()
        self.assertIn("JÁ ESTÁ NO BANCO", self.app.veredito.get())
        self.assertIn("2 tentativa(s)", self.app.detalhe.get())

    def test_numero_invalido(self):
        self.app.numero.set("4111")
        self.app.verificar()
        self.assertIn("INVÁLIDO", self.app.veredito.get())
        self.assertEqual(len(self.app.tabela.get_children()), 0)

    def test_numero_sem_validade_e_invalido(self):
        self.app.numero.set(VALID)
        self.app.verificar()
        self.assertIn("INVÁLIDO", self.app.veredito.get())
        self.assertEqual(len(self.app.tabela.get_children()), 0)

    def test_cartao_vencido_aparece_no_detalhe(self):
        self.app.numero.set(VENCIDA)
        self.app.verificar()
        self.assertIn("VENCIDO", self.app.detalhe.get())

    def test_sem_controle_de_cooldown(self):
        self.assertFalse(hasattr(self.app, "cooldown"))

    def test_esquecer_limpa_tabela(self):
        self.app.numero.set(LINHA)
        self.app.verificar()
        self.app.esquecer()
        self.assertIn("REMOVIDO", self.app.veredito.get())
        self.assertEqual(len(self.app.tabela.get_children()), 0)

    def test_consulta_sem_gravar(self):
        self.app.numero.set(LINHA)
        self.app.verificar(record=False)
        self.assertIn("não gravado", self.app.detalhe.get())
        self.assertEqual(len(self.app.tabela.get_children()), 0)


if __name__ == "__main__":
    unittest.main()

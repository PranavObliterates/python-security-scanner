from evaluate import evaluate, evaluate_sast, evaluate_dast, run_analyzer  # type: ignore


class TestSASTEvaluation:

    def test_sast_evaluation_runs(self):
        """SAST evaluation should complete without errors."""
        metrics = evaluate_sast()
        assert metrics is not None
        assert "accuracy" in metrics
        assert "precision" in metrics
        assert "recall" in metrics
        assert "f1" in metrics

    def test_sast_accuracy_above_threshold(self):
        """SAST accuracy should be at least 60%."""
        metrics = evaluate_sast()
        assert metrics["accuracy"] >= 60.0, (
            f"SAST accuracy is {metrics['accuracy']:.1f}%, expected >= 60%"
        )

    def test_sast_recall_above_threshold(self):
        """SAST recall should be at least 60% (catches most real vulnerabilities)."""
        metrics = evaluate_sast()
        assert metrics["recall"] >= 60.0, (
            f"SAST recall is {metrics['recall']:.1f}%, expected >= 60%"
        )

    def test_sast_precision_above_threshold(self):
        """SAST precision should be at least 50%."""
        metrics = evaluate_sast()
        assert metrics["precision"] >= 50.0, (
            f"SAST precision is {metrics['precision']:.1f}%, expected >= 50%"
        )


class TestDASTEvaluation:

    def test_dast_evaluation_runs(self):
        """DAST evaluation should complete without errors."""
        metrics = evaluate_dast()
        assert metrics is not None
        assert "accuracy" in metrics

    def test_dast_accuracy_above_threshold(self):
        """DAST accuracy should be at least 50%."""
        metrics = evaluate_dast()
        assert metrics["accuracy"] >= 50.0, (
            f"DAST accuracy is {metrics['accuracy']:.1f}%, expected >= 50%"
        )


class TestCombinedEvaluation:

    def test_combined_evaluation_runs(self):
        """Combined SAST+DAST evaluation should complete without errors."""
        metrics = evaluate()
        assert metrics is not None
        assert "accuracy" in metrics
        assert "precision" in metrics
        assert "recall" in metrics
        assert "f1" in metrics

    def test_combined_accuracy_above_threshold(self):
        """Combined accuracy should be at least 60%."""
        metrics = evaluate()
        assert metrics["accuracy"] >= 60.0, (
            f"Combined accuracy is {metrics['accuracy']:.1f}%, expected >= 60%"
        )


class TestRunAnalyzer:

    def test_sqli_analyzer_returns_list(self):
        """run_analyzer should return a list."""
        source = 'x = 1'
        result = run_analyzer(source, "sqli")
        assert isinstance(result, list)

    def test_xss_analyzer_returns_list(self):
        """run_analyzer should return a list for XSS."""
        source = 'x = 1'
        result = run_analyzer(source, "xss")
        assert isinstance(result, list)

    def test_secrets_analyzer_returns_list(self):
        """run_analyzer should return a list for secrets."""
        source = 'x = 1'
        result = run_analyzer(source, "secrets")
        assert isinstance(result, list)

    def test_unknown_vuln_type(self):
        """Unknown vuln type should return empty list."""
        result = run_analyzer("x = 1", "unknown_type")
        assert result == []

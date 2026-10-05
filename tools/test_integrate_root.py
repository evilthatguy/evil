import unittest
from integrate_root import adapt_patch


class PatchAdaptation(unittest.TestCase):
    def test_preserves_trace_include_and_corrects_counts(self):
        original = '--- a/fs/namespace.c\n+++ b/fs/namespace.c\n@@ -32,10 +32,20 @@\n #include "internal.h"\n \n+#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n'
        result = adapt_patch(original)
        self.assertIn('@@ -32,11 +32,21 @@', result)
        self.assertIn(' #include <trace/hooks/blk.h>\n', result)
        with self.assertRaises(ValueError):
            adapt_patch(result)

    def test_rejects_unexpected_patch(self):
        with self.assertRaises(ValueError):
            adapt_patch('@@ -33,10 +33,20 @@\n')

using System;
using System.Collections.Generic;
using System.Text;
using System.Globalization;

namespace PhishRadar.Rules;

public static class Normalizer
{
    // bỏ dấu tiếng Việt
    public static string RemoveDiacritics(string input)
    {
        if (string.IsNullOrEmpty(input)) return input;
        var formD = input.Normalize(NormalizationForm.FormD);
        var sb = new StringBuilder();
        foreach (var ch in formD)
        {
            var uc = CharUnicodeInfo.GetUnicodeCategory(ch);
            if (uc != UnicodeCategory.NonSpacingMark) sb.Append(ch);
        }
        return sb.ToString().Normalize(NormalizationForm.FormC);
    }
}
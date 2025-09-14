using System;
using System.Collections.Generic;
using System.Text;

namespace PhishRadar.Rules;
public static class HomoglyphDetector
{
    // map ký tự giống nhau về ASCII
    static readonly Dictionary<char, char> Map = new()
    {
        ['0'] = 'o',
        ['1'] = 'l',
        ['3'] = 'e',
        ['5'] = 's',
        ['7'] = 't',
        ['¡'] = 'i',
        ['Ⅰ'] = 'i',
        ['ⅼ'] = 'l',
        ['ı'] = 'i',
        ['Ｏ'] = 'o',
        ['о'] = 'o',
        ['ｅ'] = 'e',
        ['ѕ'] = 's',
        ['і'] = 'i',
        ['ӏ'] = 'l'
    };

    public static string NormalizeVisual(string s)
    {
        if (string.IsNullOrEmpty(s)) return s;
        var arr = s.ToLowerInvariant().ToCharArray();
        for (int i = 0; i < arr.Length; i++)
        {
            if (Map.TryGetValue(arr[i], out var r)) arr[i] = r;
        }
        return new string(arr);
    }

    public static bool LooksLike(string s, string target)
    {
        var a = NormalizeVisual(Normalizer.RemoveDiacritics(s));
        var b = NormalizeVisual(Normalizer.RemoveDiacritics(target));
        return a.Contains(b);
    }
}
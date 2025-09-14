using System;
using System.Collections.Generic;
using System.Text;

namespace PhishRadar.Core.Abstractions;
public interface IWhoisLookup
{
    // trả về tuổi domain (ngày) nếu biết, null nếu không
    Task<int?> GetDomainAgeDaysAsync(string host, CancellationToken ct = default);
}
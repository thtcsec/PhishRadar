using Microsoft.ML;
using Microsoft.ML.Data;
using Microsoft.ML.OnnxRuntime; // quan trọng
using PhishRadar.Training;

namespace PhishRadar.Training;

class EnhancedUrlData
{
    // Basic features (7)
    public bool Label { get; set; }
    public float UrlLength { get; set; }
    public float HasAt { get; set; }
    public float HasHyphen { get; set; }
    public float NumDigits { get; set; }
    public float IsHttp { get; set; }
    public float ContainsOtpKeyword { get; set; }
    public float ContainsBankKeyword { get; set; }

    // Advanced structural (3)
    public float HostLength { get; set; }
    public float PathLength { get; set; }
    public float SubdomainCount { get; set; }

    // Domain intelligence (3)
    public float DomainAge { get; set; }
    public float HasSuspiciousTld { get; set; }
    public float HasPunycode { get; set; }

    // Content analysis (4)
    public float FormCount { get; set; }
    public float InputCount { get; set; }
    public float SensitiveInputs { get; set; }
    public float HasUrgencyText { get; set; }

    // Sophisticated detection (6)
    public float SimilarityToKnownBank { get; set; }
    public float IPReputation { get; set; }
    public string HostingCountry { get; set; } = "";
    public float ASNReputation { get; set; }
    public float SSLCertAge { get; set; }
    public float RedirectCount { get; set; }

    // Advanced threats (6)
    public float JSObfuscated { get; set; }
    public float HiddenIframes { get; set; }
    public float FaviconSimilarity { get; set; }
    public float TextVietnamesePhishing { get; set; }
    public float ContentSimilarity { get; set; }
    public float MetaRefreshRedirect { get; set; }
}

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("🤖 PhishRadar Advanced AI Training System");
        Console.WriteLine("=========================================");

        if (args.Length > 0 && args[0] == "--eval")
        {
            await AIModelEvaluator.RunEvaluationAsync();
            return;
        }

        if (args.Length > 0 && args[0] == "--test")
        {
            await AIModelEvaluator.RunQuickTest();
            return;
        }

        // Advanced AI Training with sophisticated features
        var trainer = new AdvancedModelTrainer(seed: 42);
        await trainer.TrainAllModelsAsync();

        // Enhanced training with 30 features
        await TrainSophisticatedModel();

        Console.WriteLine("🎉 All sophisticated AI models trained successfully!");
        Console.WriteLine("Available models:");
        Console.WriteLine("  - phishradar.onnx (Advanced ensemble model)");
        Console.WriteLine("  - phishradar_sophisticated.zip (30-feature model)");
        Console.WriteLine("  - phishradar_lightgbm.onnx (LightGBM)");
        Console.WriteLine("  - phishradar_fasttree.onnx (FastTree)");
        Console.WriteLine("  - phishradar_logistic.onnx (Logistic Regression)");
        Console.WriteLine();
        Console.WriteLine("🔬 To evaluate models: dotnet run -- --eval");
        Console.WriteLine("⚡ For quick test: dotnet run -- --test");
    }

    static async Task TrainSophisticatedModel()
    {
        Console.WriteLine("\n🧠 Training Sophisticated Model with 30 Features...");
        
        var ml = new MLContext(seed: 42);

        var dataPath = Path.Combine(AppContext.BaseDirectory, "data", "phish_data.csv");
        Console.WriteLine($"[INFO] Enhanced Data: {dataPath}");
        if (!File.Exists(dataPath)) { Console.WriteLine("[ERR] Missing enhanced CSV"); return; }

        var loader = ml.Data.CreateTextLoader(new TextLoader.Options
        {
            HasHeader = true,
            Separators = new[] { ',' },
            AllowQuoting = true,
            TrimWhitespace = true,
            Columns = new[] {
                // Basic features (8)
                new TextLoader.Column(nameof(EnhancedUrlData.Label), DataKind.Boolean, 0),
                new TextLoader.Column(nameof(EnhancedUrlData.UrlLength), DataKind.Single, 1),
                new TextLoader.Column(nameof(EnhancedUrlData.HasAt), DataKind.Single, 2),
                new TextLoader.Column(nameof(EnhancedUrlData.HasHyphen), DataKind.Single, 3),
                new TextLoader.Column(nameof(EnhancedUrlData.NumDigits), DataKind.Single, 4),
                new TextLoader.Column(nameof(EnhancedUrlData.IsHttp), DataKind.Single, 5),
                new TextLoader.Column(nameof(EnhancedUrlData.ContainsOtpKeyword), DataKind.Single, 6),
                new TextLoader.Column(nameof(EnhancedUrlData.ContainsBankKeyword), DataKind.Single, 7),
                
                // Advanced structural (3)
                new TextLoader.Column(nameof(EnhancedUrlData.HostLength), DataKind.Single, 8),
                new TextLoader.Column(nameof(EnhancedUrlData.PathLength), DataKind.Single, 9),
                new TextLoader.Column(nameof(EnhancedUrlData.SubdomainCount), DataKind.Single, 10),
                
                // Domain intelligence (3)
                new TextLoader.Column(nameof(EnhancedUrlData.DomainAge), DataKind.Single, 11),
                new TextLoader.Column(nameof(EnhancedUrlData.HasSuspiciousTld), DataKind.Single, 12),
                new TextLoader.Column(nameof(EnhancedUrlData.HasPunycode), DataKind.Single, 13),
                
                // Content analysis (4)
                new TextLoader.Column(nameof(EnhancedUrlData.FormCount), DataKind.Single, 14),
                new TextLoader.Column(nameof(EnhancedUrlData.InputCount), DataKind.Single, 15),
                new TextLoader.Column(nameof(EnhancedUrlData.SensitiveInputs), DataKind.Single, 16),
                new TextLoader.Column(nameof(EnhancedUrlData.HasUrgencyText), DataKind.Single, 17),
                
                // Sophisticated detection (6)
                new TextLoader.Column(nameof(EnhancedUrlData.SimilarityToKnownBank), DataKind.Single, 18),
                new TextLoader.Column(nameof(EnhancedUrlData.IPReputation), DataKind.Single, 19),
                new TextLoader.Column(nameof(EnhancedUrlData.HostingCountry), DataKind.String, 20),
                new TextLoader.Column(nameof(EnhancedUrlData.ASNReputation), DataKind.Single, 21),
                new TextLoader.Column(nameof(EnhancedUrlData.SSLCertAge), DataKind.Single, 22),
                new TextLoader.Column(nameof(EnhancedUrlData.RedirectCount), DataKind.Single, 23),
                
                // Advanced threats (6)
                new TextLoader.Column(nameof(EnhancedUrlData.JSObfuscated), DataKind.Single, 24),
                new TextLoader.Column(nameof(EnhancedUrlData.HiddenIframes), DataKind.Single, 25),
                new TextLoader.Column(nameof(EnhancedUrlData.FaviconSimilarity), DataKind.Single, 26),
                new TextLoader.Column(nameof(EnhancedUrlData.TextVietnamesePhishing), DataKind.Single, 27),
                new TextLoader.Column(nameof(EnhancedUrlData.ContentSimilarity), DataKind.Single, 28),
                new TextLoader.Column(nameof(EnhancedUrlData.MetaRefreshRedirect), DataKind.Single, 29),
                
                // Context intelligence features (5 new ones)
                new TextLoader.Column("IsEducational", DataKind.Single, 30),
                new TextLoader.Column("HasGamblingContext", DataKind.Single, 31),
                new TextLoader.Column("PathContainsGambling", DataKind.Single, 32),
                new TextLoader.Column("HostContainsBank", DataKind.Single, 33),
                new TextLoader.Column("IsLegitimateReference", DataKind.Single, 34),
            }
        });

        var data = loader.Load(dataPath);
        var split = ml.Data.TrainTestSplit(data, testFraction: 0.2);

        var pipeline = ml.Transforms.Text.FeaturizeText("HostingCountryFeatures", nameof(EnhancedUrlData.HostingCountry))
            .Append(ml.Transforms.Concatenate("Features",
                // Basic (7)
                nameof(EnhancedUrlData.UrlLength), nameof(EnhancedUrlData.HasAt), nameof(EnhancedUrlData.HasHyphen),
                nameof(EnhancedUrlData.NumDigits), nameof(EnhancedUrlData.IsHttp), 
                nameof(EnhancedUrlData.ContainsOtpKeyword), nameof(EnhancedUrlData.ContainsBankKeyword),
                
                // Advanced structural (3)
                nameof(EnhancedUrlData.HostLength), nameof(EnhancedUrlData.PathLength), nameof(EnhancedUrlData.SubdomainCount),
                
                // Domain intelligence (3)
                nameof(EnhancedUrlData.DomainAge), nameof(EnhancedUrlData.HasSuspiciousTld), nameof(EnhancedUrlData.HasPunycode),
                
                // Content analysis (4)
                nameof(EnhancedUrlData.FormCount), nameof(EnhancedUrlData.InputCount), 
                nameof(EnhancedUrlData.SensitiveInputs), nameof(EnhancedUrlData.HasUrgencyText),
                
                // Sophisticated detection (5)
                nameof(EnhancedUrlData.SimilarityToKnownBank), nameof(EnhancedUrlData.IPReputation), 
                nameof(EnhancedUrlData.ASNReputation), nameof(EnhancedUrlData.SSLCertAge), nameof(EnhancedUrlData.RedirectCount),
                
                // Advanced threats (6)
                nameof(EnhancedUrlData.JSObfuscated), nameof(EnhancedUrlData.HiddenIframes), nameof(EnhancedUrlData.FaviconSimilarity),
                nameof(EnhancedUrlData.TextVietnamesePhishing), nameof(EnhancedUrlData.ContentSimilarity), nameof(EnhancedUrlData.MetaRefreshRedirect),
                
                // Country features
                "HostingCountryFeatures"))
            .Append(ml.Transforms.NormalizeMinMax("Features"))
            .Append(ml.BinaryClassification.Trainers.LightGbm(
                labelColumnName: nameof(EnhancedUrlData.Label), 
                featureColumnName: "Features",
                numberOfLeaves: 51,
                numberOfIterations: 300,
                minimumExampleCountPerLeaf: 3,
                learningRate: 0.08));

        var model = pipeline.Fit(split.TrainSet);

        var metrics = ml.BinaryClassification.Evaluate(
            model.Transform(split.TestSet),
            labelColumnName: nameof(EnhancedUrlData.Label), scoreColumnName: "Score");

        Console.WriteLine($"[SOPHISTICATED METRICS]");
        Console.WriteLine($"   AUC: {metrics.AreaUnderRocCurve:F4}");
        Console.WriteLine($"   Accuracy: {metrics.Accuracy:F4}");
        Console.WriteLine($"   F1 Score: {metrics.F1Score:F4}");
        Console.WriteLine($"   Precision: {metrics.PositivePrecision:F4}");
        Console.WriteLine($"   Recall: {metrics.PositiveRecall:F4}");
        Console.WriteLine($"   AUC-PR: {metrics.AreaUnderPrecisionRecallCurve:F4}");

        // Save sophisticated model
        var modelPath = Path.Combine(AppContext.BaseDirectory, "phishradar_sophisticated.zip");
        Console.WriteLine($"[INFO] Writing Sophisticated model: {modelPath}");
        ml.Model.Save(model, split.TrainSet.Schema, modelPath);
        Console.WriteLine("[OK] Saved Sophisticated model with 30 features.");
    }
}

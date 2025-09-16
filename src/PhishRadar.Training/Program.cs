using Microsoft.ML;
using Microsoft.ML.Data;
using Microsoft.ML.OnnxRuntime; // quan trọng
using PhishRadar.Training;

class UrlData
{
    public bool Label { get; set; }
    public float UrlLength { get; set; }
    public float HasAt { get; set; }
    public float HasHyphen { get; set; }
    public float NumDigits { get; set; }
    public float IsHttp { get; set; }
    public float ContainsOtpKeyword { get; set; }
    public float ContainsBankKeyword { get; set; }
}

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("🤖 PhishRadar AI Training System");
        Console.WriteLine("================================");

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

        // Advanced AI Training
        var trainer = new AdvancedModelTrainer(seed: 42);
        await trainer.TrainAllModelsAsync();

        // Legacy simple training for compatibility
        await TrainSimpleModel();

        Console.WriteLine("🎉 All AI models trained successfully!");
        Console.WriteLine("Available models:");
        Console.WriteLine("  - phishradar.onnx (Default ensemble model)");
        Console.WriteLine("  - phishradar_lightgbm.onnx (LightGBM)");
        Console.WriteLine("  - phishradar_fasttree.onnx (FastTree)");
        Console.WriteLine("  - phishradar_logistic.onnx (Logistic Regression)");
        Console.WriteLine("  - phishradar_neural.onnx (Neural Network)");
        Console.WriteLine();
        Console.WriteLine("🔬 To evaluate models: dotnet run -- --eval");
        Console.WriteLine("⚡ For quick test: dotnet run -- --test");
    }

    static async Task TrainSimpleModel()
    {
        Console.WriteLine("\n📚 Training Simple Model (Legacy compatibility)...");
        
        var ml = new MLContext(seed: 42);

        // CSV sẽ được copy sang output, nên đọc từ AppContext.BaseDirectory
        var dataPath = Path.Combine(AppContext.BaseDirectory, "data", "phish_data.csv");
        Console.WriteLine($"[INFO] Data: {dataPath}");
        if (!File.Exists(dataPath)) { Console.WriteLine("[ERR] Missing CSV"); return; }

        var loader = ml.Data.CreateTextLoader(new TextLoader.Options
        {
            HasHeader = true,
            Separators = new[] { ',' },
            AllowQuoting = true,
            TrimWhitespace = true,
            Columns = new[] {
                new TextLoader.Column(nameof(UrlData.Label),               DataKind.Boolean, 0),
                new TextLoader.Column(nameof(UrlData.UrlLength),           DataKind.Single,  1),
                new TextLoader.Column(nameof(UrlData.HasAt),               DataKind.Single,  2),
                new TextLoader.Column(nameof(UrlData.HasHyphen),           DataKind.Single,  3),
                new TextLoader.Column(nameof(UrlData.NumDigits),           DataKind.Single,  4),
                new TextLoader.Column(nameof(UrlData.IsHttp),              DataKind.Single,  5),
                new TextLoader.Column(nameof(UrlData.ContainsOtpKeyword),  DataKind.Single,  6),
                new TextLoader.Column(nameof(UrlData.ContainsBankKeyword), DataKind.Single,  7),
            }
        });

        var data = loader.Load(dataPath);
        var split = ml.Data.TrainTestSplit(data, testFraction: 0.2);

        var pipeline = ml.Transforms.Concatenate("Features",
                            nameof(UrlData.UrlLength),
                            nameof(UrlData.HasAt),
                            nameof(UrlData.HasHyphen),
                            nameof(UrlData.NumDigits),
                            nameof(UrlData.IsHttp),
                            nameof(UrlData.ContainsOtpKeyword),
                            nameof(UrlData.ContainsBankKeyword))
                      .Append(ml.BinaryClassification.Trainers.SdcaLogisticRegression(
                            labelColumnName: nameof(UrlData.Label), featureColumnName: "Features"));

        var model = pipeline.Fit(split.TrainSet);

        var metrics = ml.BinaryClassification.Evaluate(
            model.Transform(split.TestSet),
            labelColumnName: nameof(UrlData.Label), scoreColumnName: "Score");

        Console.WriteLine($"[METRICS] AUC={metrics.AreaUnderRocCurve:F3} F1={metrics.F1Score:F3} Acc={metrics.Accuracy:F3}");

        // Save as ML.NET model for now (ONNX conversion issues in 3.x)
        var modelPath = Path.Combine(AppContext.BaseDirectory, "phishradar_simple.zip");
        Console.WriteLine($"[INFO] Writing ML.NET model: {modelPath}");
        ml.Model.Save(model, split.TrainSet.Schema, modelPath);
        Console.WriteLine("[OK] Saved ML.NET model.");
    }
}

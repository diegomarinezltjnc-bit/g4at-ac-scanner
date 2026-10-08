using System.Windows.Forms;

namespace G4atScanner;

static class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        var cfg = AppConfig.Load(args);
        Application.Run(new MainForm(cfg));
    }
}

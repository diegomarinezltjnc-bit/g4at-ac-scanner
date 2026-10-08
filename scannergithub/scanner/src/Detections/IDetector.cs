namespace G4atScanner;

// Un detector = una categoría de análisis. Cada uno busca EVIDENCIA DE TRAMPAS
// y devuelve hallazgos. No recoge datos personales ajenos a trampas.
public interface IDetector
{
    string Title { get; }   // lo que ve el usuario mientras corre
    string Sub { get; }     // subtítulo técnico
    // log(mensaje, esRojo) permite escribir en la consola en vivo de la UI.
    Task<List<Finding>> RunAsync(Action<string, bool> log);
}

<?php
// Chemin vers le fichier CSV
$csvFile = '/var/www/html/api/alertessiem.csv';

// Vérifier si le fichier existe
if (!file_exists($csvFile)) {
    echo json_encode([
        'success' => false,
        'message' => 'Le fichier d\'alertes n\'existe pas'
    ]);
    exit;
}

try {
    // Lire directement le contenu du fichier
    $content = file_get_contents($csvFile);
    if ($content === false) {
        throw new Exception('Impossible de lire le fichier CSV');
    }
    
    // Diviser le contenu en lignes
    $lines = explode("\n", $content);
    $alerts = [];
    
    // Ignorer la première ligne si elle contient des en-têtes
    $startIndex = (count($lines) > 0 && preg_match('/ID|IP|Source|Date/i', $lines[0])) ? 1 : 0;
    
    // Traiter chaque ligne
    for ($i = $startIndex; $i < count($lines); $i++) {
        $line = trim($lines[$i]);
        if (empty($line)) continue;
        
        // Diviser la ligne en ses composants (en supposant qu'ils sont séparés par des virgules)
        $parts = explode(',', $line);
        
        // Créer un tableau pour chaque alerte
        $alert = [
            'id' => $i
        ];
        
        // Vérifier qu'il y a assez de parties pour former une alerte
        if (count($parts) >= 4) {
            // Assignation correcte des champs
            // Basé sur l'exemple, le format semble être:
            // TYPE,IP_SOURCE,IP_DEST,CRITICITÉ,DATE
            $alert['type'] = trim($parts[0]);
            $alert['source_ip'] = trim($parts[1]);
            $alert['dest_ip'] = trim($parts[2]);
            
            // La date semble être la dernière partie (5ème élément si disponible)
            if (isset($parts[4]) && !empty(trim($parts[4]))) {
                $alert['date'] = trim($parts[4]);
            } else {
                $alert['date'] = '-';
            }
            
            // La criticité semble être la 4ème partie
            if (isset($parts[3]) && !empty(trim($parts[3]))) {
                $alert['criticality'] = trim($parts[3]);
            } else {
                $alert['criticality'] = '-';
            }
        } else if (count($parts) == 3) {
            // Format minimal: TYPE,IP_SOURCE,IP_DEST
            $alert['type'] = trim($parts[0]);
            $alert['source_ip'] = trim($parts[1]);
            $alert['dest_ip'] = trim($parts[2]);
            $alert['date'] = '-';
            $alert['criticality'] = '-';
        }
        
        $alerts[] = $alert;
    }
    
    // Renvoyer les données au format JSON
    echo json_encode([
        'success' => true,
        'alerts' => $alerts
    ]);
    
} catch (Exception $e) {
    echo json_encode([
        'success' => false,
        'message' => 'Erreur: ' . $e->getMessage()
    ]);
}
?>
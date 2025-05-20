<?php
// Définir l'en-tête pour indiquer que la réponse est au format JSON
header('Content-Type: application/json');

// Chemin vers le fichier CSV
$csv_file = '/var/www/html/api/uploads/machine_bloque.csv';

// Tableau pour stocker les données
$response = array();

// Vérifier si le fichier existe
if (file_exists($csv_file)) {
    try {
        // Ouvrir le fichier en lecture
        $file = fopen($csv_file, 'r');
        
        if ($file) {
            // Lire la première ligne pour obtenir les en-têtes
            $headers = fgetcsv($file, 0, ",");
            
            // Vérifier si les en-têtes existent et sont au bon format
            if ($headers && count($headers) >= 3) {
                // Initialiser un tableau pour stocker les données des IP bloquées
                $blocked_ips = array();
                $id = 1; // Identifiant unique pour chaque entrée
                
                // Lire les données ligne par ligne
                while (($row = fgetcsv($file, 0, ",")) !== FALSE) {
                    // S'assurer que la ligne a au moins 3 colonnes
                    if (count($row) >= 3) {
                        $blocked_ip = array(
                            'id' => $id++,
                            'attacked_machine' => $row[0],
                            'blocked_machine' => $row[1],
                            'date' => $row[2]
                        );
                        
                        // Ajouter les données supplémentaires si elles existent
                        for ($i = 3; $i < count($row) && $i < count($headers); $i++) {
                            $blocked_ip[$headers[$i]] = $row[$i];
                        }
                        
                        $blocked_ips[] = $blocked_ip;
                    }
                }
                
                // Fermer le fichier
                fclose($file);
                
                // Préparer la réponse
                $response = array(
                    'success' => true,
                    'message' => 'Données chargées avec succès',
                    'blocked_ips' => $blocked_ips,
                    'count' => count($blocked_ips)
                );
            } else {
                $response = array(
                    'success' => false,
                    'message' => 'Format de fichier CSV invalide. Les en-têtes attendus sont manquants.'
                );
            }
        } else {
            $response = array(
                'success' => false,
                'message' => 'Impossible d\'ouvrir le fichier CSV.'
            );
        }
    } catch (Exception $e) {
        $response = array(
            'success' => false,
            'message' => 'Erreur lors de la lecture du fichier: ' . $e->getMessage()
        );
    }
} else {
    $response = array(
        'success' => false,
        'message' => 'Le fichier CSV n\'existe pas.'
    );
}

// Retourner la réponse au format JSON
echo json_encode($response);
?>
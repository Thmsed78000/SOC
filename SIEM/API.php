<?php

header ('Content-Type: application/ json' ) ;

// Dossier o? stocker les fichiers

$upload_directory = '/var/www/html/api/uploads/';

// V@rifier si le dossier existe, sinon le cr@er

if (!is_dir($upload_directory)) {

    mkdir($upload_directory, 0777, true) ;

}

// V@rifier si des fichiers ont 0t@ envoy@s

if (empty($_FILES)) {

    echo json_encode( ["error" => "Aucun fichier re@u. VOrifiez l'envoi en multipart/form-data."]);

    exit;

}

$uploaded_files = [];

foreach ($_FILES as $key => $file) {

    if ($file['error'] !== UPLOAD_ERR_OK) {

        echo json_encode(["error" => "Erreur lors de l'upload du fichier $key. Code: " . $file['error' ]]);

        continue;

    }
// VOrifier que c'est bien un fichier CSV

$file_extension = pathinfo($file['name' ], PATHINFO_EXTENSION) ;

if ($file_extension !== 'csv') {

    echo json_encode(["error" => "Le fichier $key doit @tre au format CSV. "]) ;

    continue;

}

// DOfinir le chemin final du fichier (@viter 1'@crasement)

$destination_path = $upload_directory . basename($file['name' ]);


// Si le fichier existe d@j@, on va l'ouvrir en mode append (ajouter les nouvelles donn@es)

if (file_exists($destination_path)) {

    $file_to_write = fopen($destination_path, "a"); // Ouvrir le fichier en mode append

    if ($file_to_write) {

        $uploaded_files[] = [

            => basename($file['name' ]),

            "file_path" => $destination_path,

            "status" => "append"
        ];

    } else {

echo json_encode( ["error" => "Impossible d'ouvrir le fichier existant $key."]) ;

continue;

} else {

// Si le fichier n'existe pas, on le cr@e

$file_to_write = fopen($destination_path, "w"); // Ouvrir le fichier en mode @criture

if ($file_to_write) {

    $uploaded_files[] = [
    
    "file_name" =>
    basename($file['name' ]),
    
    "file_path" => $destination_path,
    
    "status" => "success"

    ];
    
    } else {
    
    echo json_encode( ["error" => "Erreur lors de la cr@ation du fichier $key. "]) ;
    
    continue;

    }
}
    
    // Ajouter le contenu du fichier envoy@ @ la fin du fichier existant
    
    if (fwrite($file_to_write, file_get_contents($file['tmp_name' ]) )) {
    
    fclose($file_to_write);
    
    } else {
    
    echo json_encode( ["error" => "Erreur lors de l'ajout du contenu du fichier $key. "]) ;
    
    continue;

    }

} 
    
    //ROponse finale

    echo json_encode([

        "message" => "Upload termin ?. "

    ]);

    ?>
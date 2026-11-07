#include "mainwindow.h"
#include <QApplication>
#include <QDebug>

extern "C" {
#include <sodium.h>
}

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    a.setApplicationName("G8t");
    a.setOrganizationName("Cyze");

    // Initialisation de libsodium
    if (sodium_init() < 0) {
        qCritical() << "Erreur fatale : Impossible d'initialiser libsodium.";
        return -1;
    }
    qDebug() << "Libsodium initialisé avec succès.";

    MainWindow w;
    w.show();
    return a.exec();
}

import pandas as pd  # data processing, CSV file I/O (e.g. pd.read_csv)
import seaborn as sns
import sys
import argparse

from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neural_network import MLPClassifier
from sklearn.inspection import DecisionBoundaryDisplay
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, auc, roc_curve, f1_score
from sklearn.decomposition import PCA
from sklearn import model_selection
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import NearMiss

models = []
models.append(('LR', LogisticRegression(max_iter=10000)))
models.append(('KNN9', KNeighborsClassifier(n_neighbors=9)))
models.append(('KNN7', KNeighborsClassifier(n_neighbors=7)))
models.append(('KNN5', KNeighborsClassifier()))
models.append(('KNN3', KNeighborsClassifier(n_neighbors=3)))
models.append(('KNN1', KNeighborsClassifier(n_neighbors=1)))
models.append(('RF', RandomForestClassifier()))
models.append(('CART', DecisionTreeClassifier()))
models.append(('NB', GaussianNB()))
models.append(('SVM', SVC()))
models.append(('MLP', MLPClassifier()))

# MLA = [
#     # Logistinc Regression
#     LogisticRegression(),

#     # Random Forest
#     RandomForestClassifier(),

#     # SVM
#     SVC(probability=True),

#     # Trees
#     DecisionTreeClassifier(),

#     # Naive Bayes
#     GaussianNB(),

#     # Nearest Neighbor
#     KNeighborsClassifier(n_neighbors=9),
#     KNeighborsClassifier(n_neighbors=7),
#     KNeighborsClassifier(),
#     KNeighborsClassifier(n_neighbors=3),
#     KNeighborsClassifier(n_neighbors=1),

#     # FNN
#     MLPClassifier(),
# ]


def printUsage():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                        help='Muestra este mensaje y termina el programa')
    parser.add_argument('-o', dest='accumulate', action='store_const',
                        const=sum, default=max,
                        help='Aplica oversampling sobre la clase con minoría')
    parser.add_argument('-u', dest='accumulate', action='store_const',
                        const=sum, default=max,
                        help='Aplica undersampling sobre la clase con mayoría')

    args = parser.parse_args()
    print(args.accumulate(args.integers))


def buildDataset(resample=""):
    benign = pd.read_csv("./dataset_benign.csv")
    malware = pd.read_csv("./dataset_malware.csv")

    data = pd.concat([benign, malware], ignore_index=True)
    X = data.drop(['Name', 'Malware'], axis=1)
    y = data['Malware']

    if (resample == "-o"):
        print("Aplicando oversampling...")
        smote = SMOTE(random_state=42)
        X, y = smote.fit_resample(X, y)
    elif (resample == "-u"):
        print("\n\n\nAplicando undersampling...")
        nearmiss = NearMiss(version=1)
        X, y = nearmiss.fit_resample(X, y)

    print("Número de muestras totales:", len(X), "\n\n\n")
    # plt.figure(figsize=(8, 6))
    # ax = sns.countplot(y=y)
    # # ax.set_xticklabels(['Benign', 'Malware'])
    return X, y


def trainTest(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=101)

    sc = StandardScaler().fit(X_train)

    X_train = sc.transform(X_train)
    X_test = sc.transform(X_test)

    # Selección de características (provisional)
    # skpca = PCA(n_components=10)

    # X_train = skpca.fit_transform(X_train)
    # X_test = skpca.transform(X_test)

    print(f'Número de características usadas: {X_train.shape[1]} \n\n\n')

    return X_train, X_test, y_train, y_test


def crossValidationScore(X_train, y_train):
    # evaluate each model in turn
    results = []
    names = []
    scoring = 'accuracy'
    print("COMPARACIÓNN DE ALGORITMOS MEDIANTE CROSS-VALIDATION")
    for name, model in models:
        kfold = model_selection.KFold(n_splits=10)
        cv_results = model_selection.cross_val_score(
            model, X_train, y_train, cv=kfold, scoring=scoring)
        results.append(cv_results)
        names.append(name)
        msg = "%s: %f (%f)" % (name, cv_results.mean(), cv_results.std())
        print(msg)
    print("\n\n\n")


def compareMLAs(X_train, X_test, y_train, y_test):
    MLA_columns = []
    MLA_compare = pd.DataFrame(columns=MLA_columns)

    row_index = 0
    for name, model in models:

        predicted = model.fit(X_train, y_train).predict(X_test)

        fp, tp, th = roc_curve(y_test, predicted)
        MLA_name = name
        MLA_compare.loc[row_index, 'MLA used'] = MLA_name
        MLA_compare.loc[row_index, 'Train Accuracy'] = round(
            model.score(X_train, y_train), 4)
        MLA_compare.loc[row_index, 'Test Accuracy'] = round(
            model.score(X_test, y_test), 4)
        MLA_compare.loc[row_index, 'Precission'] = precision_score(
            y_test, predicted)
        MLA_compare.loc[row_index, 'Recall'] = recall_score(y_test, predicted)
        MLA_compare.loc[row_index, 'F1-Score'] = f1_score(
            y_test, predicted)
        MLA_compare.loc[row_index, 'AUC'] = auc(fp, tp)

        row_index += 1

    MLA_compare.sort_values(by=['Test Accuracy'],
                            ascending=False, inplace=True)
    print(MLA_compare)


# Flujo principal del programa
if len(sys.argv) == 1:
    X, y = buildDataset()
    X_train, X_test, y_train, y_test = trainTest(X, y)

elif len(sys.argv) == 2:
    if sys.argv[1] == "-o" or sys.argv[1] == "-u":
        resample = sys.argv[1]
        X, y = buildDataset(resample)
        X_train, X_test, y_train, y_test = trainTest(X, y)
    else:
        printUsage()
        sys.exit()
elif len(sys.argv) == 3:
    printUsage()
    sys.exit()

crossValidationScore(X_train, y_train)
compareMLAs(X_train, X_test, y_train, y_test)

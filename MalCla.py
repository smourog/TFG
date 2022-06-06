import pandas as pd  # data processing, CSV file I/O (e.g. pd.read_csv)
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.preprocessing import StandardScaler, normalize
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.inspection import DecisionBoundaryDisplay
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, auc, roc_curve
from sklearn import svm, model_selection, tree, linear_model, neighbors, naive_bayes, ensemble, discriminant_analysis, gaussian_process, preprocessing

# names = [
#     "KNN",
#     "SVM",
#     "Decision Tree",
#     "Random Forest",
#     "RNA",
#     "Naive Bayes",
# ]

# classifiers = [
#     KNeighborsClassifier(5),
#     SVC(kernel="linear", C=0.025),
#     DecisionTreeClassifier(max_depth=5),
#     RandomForestClassifier(max_depth=5, n_estimators=10, max_features=1),
#     MLPClassifier(alpha=1, max_iter=1000),
#     GaussianNB(),
# ]

benign = pd.read_csv("./dataset_benign.csv")

benign.info()

malware = pd.read_csv("./dataset_malware.csv")

malware.info()

data = pd.concat([benign, malware], ignore_index=True)

# data = data.sample(frac=1, ignore_index=True)

data.head()

data.info()

plt.figure(figsize=(8, 6))
ax = sns.countplot(data['Malware'])
ax.set_xticklabels(['Benign', 'Malware'])

# #The target is Malware Column {0=Benign, 1=Malware}
X = data.drop(['Name', 'Malware'], axis=1)
y = data['Malware']

X.info()

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=0)

sc = StandardScaler().fit(X_train)

X_train = sc.transform(X_train)
# X_train = sc.fit_transform(X_train)
X_test = sc.transform(X_test)

X_train

models = []

models.append(('LR', LogisticRegression(max_iter=10000)))
models.append(('KNN', KNeighborsClassifier()))
models.append(('DT', DecisionTreeClassifier()))
models.append(('NB', GaussianNB()))
# models.append(('SVM', SVC()))

models

# evaluate each model in turn
results = []
names = []
scoring = 'accuracy'
for name, model in models:
    kfold = model_selection.KFold(n_splits=10)
    cv_results = model_selection.cross_val_score(
        model, X_train, y_train, cv=kfold, scoring=scoring)
    results.append(cv_results)
    names.append(name)
    msg = "%s: %f (%f)" % (name, cv_results.mean(), cv_results.std())
    print(msg)
# boxplot algorithm comparison
fig = plt.figure(figsize=[20, 10])
fig.suptitle('Comparison between different MLAs')
ax = fig.add_subplot(111)
plt.boxplot(results)
ax.set_xticklabels(names)
plt.show()

# Application of all Machine Learning methods
MLA = [
    # GLM
    linear_model.LogisticRegressionCV(max_iter=10000),

    # #Ensemble Methods
    # ensemble.RandomForestClassifier(),
    # #SVM
    # svm.SVC(probability=True),
    # #Trees
    tree.DecisionTreeClassifier(),

    # Navies Bayes
    naive_bayes.GaussianNB(),

    # Nearest Neighbor
    neighbors.KNeighborsClassifier(),
]

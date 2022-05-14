import pickle
import warnings

warnings.filterwarnings("ignore")
load = pickle.load(open('urlclassify.pkl','rb'))

result = load.predict(['youtube.com/'])

print(result)
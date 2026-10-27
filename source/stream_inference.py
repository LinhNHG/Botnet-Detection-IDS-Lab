"""Replay new flow feature rows using the saved IDS threshold."""
import argparse,json
from pathlib import Path
import joblib,numpy as np,pandas as pd

def infer(csv,root,output):
    root=Path(root); cfg=json.loads((root/'model/threshold.json').read_text())
    df=pd.read_csv(csv,low_memory=False);df.columns=df.columns.str.strip()
    missing=set(cfg['feature_columns'])-set(df.columns)
    if missing: raise ValueError('Missing required feature columns: '+str(sorted(missing)))
    X=df[cfg['feature_columns']].apply(pd.to_numeric,errors='coerce').replace([np.inf,-np.inf],np.nan)
    model=joblib.load(root/'model/ids_model.joblib');prob=model.predict_proba(X)[:,1]
    result=df.copy();result['Attack_probability']=prob;result['Threshold']=cfg['threshold']
    result['Decision']=np.where(prob>=cfg['threshold'],'BOT ALERT','NORMAL')
    result.to_csv(output,index=False); print(result[['Attack_probability','Threshold','Decision']].head(10).to_string(index=False))
    return result
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--csv',required=True);p.add_argument('--root',default=str(Path(__file__).resolve().parents[1]));p.add_argument('--output',default='flow_predictions.csv');a=p.parse_args();infer(a.csv,a.root,a.output)

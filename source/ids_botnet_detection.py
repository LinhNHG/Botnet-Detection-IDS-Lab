"""CICIDS2017 Bot IDS. Run: python ids_botnet_detection.py --csv PATH --output DIR
SMOTE is implemented explicitly using sklearn nearest neighbours (no imblearn dependency).
Load the exported artifact with joblib.load; it contains only standard sklearn objects.
"""
import argparse, json, platform, time, warnings
from pathlib import Path
from typing import cast
from matplotlib.container import BarContainer
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from sklearn import __version__ as sklearn_version
from sklearn.base import BaseEstimator, ClassifierMixin, clone
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler, RobustScaler, FunctionTransformer
from sklearn.feature_selection import RFE, VarianceThreshold
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, GridSearchCV
from sklearn.neighbors import NearestNeighbors
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
 roc_auc_score, average_precision_score, confusion_matrix, roc_curve, precision_recall_curve)

SEED=42
DROP=['Flow ID','Source IP','Destination IP','Source Port','Timestamp','Fwd Header Length.1']

def smote(X,y,random_state=42,k=5):
    """Binary SMOTE, minority to majority count; interpolate random k-nearest neighbours."""
    X=np.asarray(X,dtype=float); y=np.asarray(y,dtype=int)
    counts=np.bincount(y); minority=int(np.argmin(counts)); n=int(max(counts)-min(counts))
    if n==0: return X,y
    M=X[y==minority]; k=min(k,len(M)-1)
    if k<1: raise ValueError('SMOTE requires at least two minority observations')
    neighbors = NearestNeighbors(n_neighbors=k+1).fit(M)
    indices = np.asarray(neighbors.kneighbors(M, return_distance=False), dtype=np.intp)
    nn = indices[:, 1:]
    rng=np.random.default_rng(random_state); a=rng.integers(0,len(M),n)
    b=nn[a,rng.integers(0,k,n)]; u=rng.random((n,1))
    return np.vstack([X,M[a]+u*(M[b]-M[a])]),np.r_[y,np.full(n,minority)]

class SMOTEClassifier(ClassifierMixin,BaseEstimator):
    """Resamples only inside fit, including each GridSearchCV training fold."""
    def __init__(self,estimator: RandomForestClassifier | None=None,random_state=42):
        self.estimator=estimator; self.random_state=random_state
    def fit(self,X,y):
        Xr,yr=smote(X,y,self.random_state)
        if self.estimator is None:
            raise ValueError('SMOTEClassifier requires a RandomForestClassifier estimator')
        self.estimator_ = cast(RandomForestClassifier, clone(self.estimator))
        self.estimator_.fit(Xr, yr)
        self.classes_=self.estimator_.classes_; self.n_features_in_=X.shape[1]
        return self
    def predict(self,X): return self.estimator_.predict(X)
    def predict_proba(self,X): return self.estimator_.predict_proba(X)

def metrics(y,p,t=.5):
    pred=(np.asarray(p)>=t).astype(int); tn,fp,fn,tp=confusion_matrix(y,pred,labels=[0,1]).ravel()
    return dict(Accuracy=accuracy_score(y,pred),Precision=precision_score(y,pred,zero_division=0),
       Recall=recall_score(y,pred,zero_division=0),F1=f1_score(y,pred,zero_division=0),
       ROC_AUC=roc_auc_score(y,p),PR_AUC=average_precision_score(y,p),TN=int(tn),FP=int(fp),FN=int(fn),TP=int(tp))

def main(csv,output):
    out=Path(output)
    for d in ['results','figures','model','source','notebook']: (out/d).mkdir(parents=True,exist_ok=True)
    res=out/'results'; fig=out/'figures'; start=time.time()
    def savefig(name): plt.tight_layout(); plt.savefig(fig/name,dpi=170,bbox_inches='tight'); plt.close()
    def log(x): print(x,flush=True)
    raw=pd.read_csv(csv,low_memory=False); raw.columns=raw.columns.str.strip(); raw.index.name='source_row_0based'
    labels=raw.Label.astype(str).str.strip()
    if not labels.isin(['BENIGN','Bot']).all(): raise ValueError('Unexpected labels')
    numeric=raw.drop(columns=['Label']).select_dtypes(include=np.number)
    schema=pd.DataFrame({'Feature':raw.columns,'dtype':raw.dtypes.astype(str).values,
      'missing':raw.isna().sum().values,'infinite':[int(np.isinf(raw[c]).sum()) if pd.api.types.is_numeric_dtype(raw[c]) else 0 for c in raw]})
    schema.to_csv(res/'data_schema.csv',index=False)
    eda={'raw_shape':list(raw.shape),'raw_class_counts':labels.value_counts().to_dict(),
      'raw_missing_cells':int(raw.isna().sum().sum()),'raw_infinite_cells':int(np.isinf(numeric).sum().sum()),
      'raw_exact_duplicates':int(raw.duplicated().sum()),'dropped_identifier_columns':DROP}
    raw.groupby(labels).size().rename('Count').to_csv(res/'class_counts.csv')
    plt.figure(figsize=(7, 4))
    ax = sns.countplot(x=labels, order=['BENIGN', 'Bot'])
    ax.set_ylim(0, float(labels.value_counts().max()) * 1.18)
    for container in ax.containers:
        if isinstance(container, BarContainer):
            ax.bar_label(container, fmt='%.0f', padding=5)
    ax.set_title('Original class distribution', pad=15)
    ax.set_xlabel('Label')
    ax.set_ylabel('Number of flows')
    savefig('class_distribution.png')
    raw=raw.loc[~raw.duplicated()].copy()
    X=raw.drop(columns=['Label']+DROP,errors='ignore').apply(pd.to_numeric,errors='coerce').replace([np.inf,-np.inf],np.nan)
    y=raw.Label.str.strip().map({'BENIGN':0,'Bot':1}).astype(int)
    # Prevent identical predictor rows from appearing in different splits.
    # Contradictory predictor groups are excluded; consistent groups keep one record.
    hashes=pd.util.hash_pandas_object(X,index=False)
    group_labels=y.groupby(hashes).nunique(); conflicts=hashes.isin(group_labels[group_labels>1].index)
    eda['conflicting_predictor_rows_removed']=int(conflicts.sum())
    X=X.loc[~conflicts]; y=y.loc[X.index]
    dup=X.duplicated(); eda['additional_predictor_duplicates_removed']=int(dup.sum())
    X=X.loc[~dup]; y=y.loc[X.index]; raw=raw.loc[X.index]
    eda['clean_shape']=list(X.shape); eda['clean_class_counts']=y.value_counts().to_dict()
    Xtrain,Xtest,ytrain,ytest=train_test_split(X,y,test_size=.30,stratify=y,random_state=SEED)
    Xdev,Xval,ydev,yval=train_test_split(Xtrain,ytrain,test_size=.20,stratify=ytrain,random_state=SEED)
    assert not set(Xdev.index)&set(Xtest.index) and not set(Xval.index)&set(Xtest.index)
    split=pd.DataFrame({'source_row_0based':X.index,'split':['development' if i in Xdev.index else 'validation' if i in Xval.index else 'test' for i in X.index],'y':y.values})
    split.to_csv(res/'split_manifest.csv',index=False)
    eda['splits']={n:{'rows':len(a),'benign':int((b==0).sum()),'bot':int((b==1).sum())} for n,a,b in [('train70',Xtrain,ytrain),('development56',Xdev,ydev),('validation14',Xval,yval),('test30',Xtest,ytest)]}
    (res/'eda.json').write_text(json.dumps(eda,indent=2),encoding='utf8'); log(eda)
    corr=Xdev.corr(); corr.to_csv(res/'correlation_matrix.csv')
    pairs=[(a,b,float(corr.loc[a,b])) for i,a in enumerate(corr.columns) for b in corr.columns[i+1:] if abs(corr.loc[a,b])>.90]
    pd.DataFrame(pairs,columns=['Feature_1','Feature_2','Correlation']).to_csv(res/'high_correlation_pairs.csv',index=False)
    plt.figure(figsize=(13,11)); sns.heatmap(corr,cmap='coolwarm',vmin=-1,vmax=1,xticklabels=False,yticklabels=False); plt.title('Development data Pearson correlation (full labels in CSV)'); savefig('correlation_matrix.png')
    # Describe real outliers after train-only median imputation.
    imp=SimpleImputer(strategy='median',keep_empty_features=True).fit(Xdev)
    di=imp.transform(Xdev)
    scales=[]
    for name,scaler in [('StandardScaler',StandardScaler()),('RobustScaler',RobustScaler())]:
        z=scaler.fit_transform(di)
        for feature in ['Flow Bytes/s','Flow Packets/s','Flow Duration']:
            j=list(Xdev.columns).index(feature)
            scales.append({'Scaler':name,'Feature':feature,'Median':np.median(z[:,j]),'Q25':np.quantile(z[:,j],.25),'Q75':np.quantile(z[:,j],.75),'P99':np.quantile(z[:,j],.99),'Max':z[:,j].max()})
    pd.DataFrame(scales).to_csv(res/'scaling_comparison.csv',index=False)
    def pre(scaler='robust'):
        return Pipeline([('imputer',SimpleImputer(strategy='median',keep_empty_features=True)),('variance',VarianceThreshold()),
          ('scale',RobustScaler() if scaler=='robust' else StandardScaler()),
          ('rfe',RFE(RandomForestClassifier(n_estimators=30,max_depth=12,class_weight='balanced',random_state=SEED,n_jobs=1),n_features_to_select=12,step=20))])
    prep=pre(); A=prep.fit_transform(Xdev,ydev); V=prep.transform(Xval); T=prep.transform(Xtest)
    valid=prep.named_steps['variance'].get_support(); names=X.columns[valid]; rfe=prep.named_steps['rfe']
    ranks=pd.DataFrame({'Feature':names,'Selected':rfe.support_,'Rank':rfe.ranking_})
    ranks=pd.concat([ranks,pd.DataFrame({'Feature':X.columns[~valid],'Selected':False,'Rank':np.nan})]); ranks.to_csv(res/'feature_selection.csv',index=False)
    selected=list(names[rfe.support_]); log('RFE selected: '+str(selected))
    models={'Decision Tree':DecisionTreeClassifier(max_depth=12,min_samples_leaf=2,random_state=SEED),
      'Random Forest':RandomForestClassifier(n_estimators=100,max_depth=None,n_jobs=1,random_state=SEED),
      'Gradient Boosting':GradientBoostingClassifier(n_estimators=100,max_depth=3,random_state=SEED)}
    Ar,yr=smote(A,ydev); eda['smote_counts']={str(k):int(v) for k,v in zip(*np.unique(yr,return_counts=True))}
    candidates={}; rows=[]; valrows=[]
    for experiment,xx,yy in [('A Original',A,ydev),('B SMOTE',Ar,yr)]:
        for name,model in models.items():
            key=name+' | '+experiment; log('Training '+key)
            m=clone(model).fit(xx,yy); candidates[key]=(prep,m)
            rows.append(dict(Model=name,Experiment=experiment,**metrics(ytest,m.predict_proba(T)[:,1])))
            valrows.append(dict(Candidate=key,**metrics(yval,m.predict_proba(V)[:,1])))
    # Explicit end-to-end CV: imputation/scaling/RFE/SMOTE fitted separately inside every fold.
    cache=out.parent/'.ids_cv_cache'
    gridpipe=Pipeline([('prep',pre()),('clf',SMOTEClassifier(RandomForestClassifier(random_state=SEED,n_jobs=1)))],memory=str(cache))
    grid={'clf__estimator__n_estimators':[40,80],'clf__estimator__max_depth':[10,None],'clf__estimator__min_samples_split':[2,10]}
    log('GridSearchCV: 8 configurations x 3 folds; preprocessing and SMOTE inside folds')
    search=GridSearchCV(gridpipe,grid,cv=StratifiedKFold(3,shuffle=True,random_state=SEED),scoring='f1',n_jobs=1,return_train_score=True,error_score='raise')
    search.fit(Xdev,ydev)
    pd.DataFrame(search.cv_results_).to_csv(res/'gridsearch_results.csv',index=False)
    best=search.best_estimator_; key='Random Forest Tuned | B SMOTE'; candidates[key]=(best.named_steps['prep'],best.named_steps['clf'].estimator_)
    rows.append(dict(Model='Random Forest Tuned',Experiment='B SMOTE',**metrics(ytest,best.predict_proba(Xtest)[:,1])))
    valrows.append(dict(Candidate=key,**metrics(yval,best.predict_proba(Xval)[:,1])))
    tuning={'best_params':search.best_params_,'best_cv_f1':float(search.best_score_),'folds':3,'scoring':'f1'}
    (res/'tuning.json').write_text(json.dumps(tuning,indent=2)); log(tuning)
    pd.DataFrame(rows).to_csv(res/'model_comparison.csv',index=False)
    pd.DataFrame(valrows).to_csv(res/'validation_model_comparison.csv',index=False)
    # Extra StandardScaler experiment using otherwise identical RFE and SMOTE RF.
    pstd=pre('standard'); ds=pstd.fit_transform(Xdev,ydev); xs,ys=smote(ds,ydev)
    ms=clone(models['Random Forest']).fit(xs,ys)
    stdrow=dict(Candidate='RF SMOTE StandardScaler',**metrics(yval,ms.predict_proba(pstd.transform(Xval))[:,1]))
    pd.DataFrame([stdrow,dict(Candidate='RF SMOTE RobustScaler',**metrics(yval,candidates['Random Forest | B SMOTE'][1].predict_proba(V)[:,1]))]).to_csv(res/'scaler_validation_metrics.csv',index=False)
    # Select model AND threshold using validation exclusively, never test outcomes.
    sweep=[]
    for name,(pp,mm) in candidates.items():
        pv=mm.predict_proba(pp.transform(Xval))[:,1]
        for t in np.round(np.arange(.1,1,.1),2): sweep.append(dict(Candidate=name,Threshold=t,**metrics(yval,pv,t)))
    sweep=pd.DataFrame(sweep); sweep.to_csv(res/'validation_thresholds_all_models.csv',index=False)
    feasible=sweep[sweep.Recall>=.95]
    if len(feasible): chosen=feasible.sort_values(['Precision','Recall','F1','Threshold'],ascending=[False,False,False,False]).iloc[0]; status='Validation recall target achieved'
    else: chosen=sweep.sort_values(['Recall','Precision','F1'],ascending=False).iloc[0]; status='No validation threshold on requested grid meets 95%; report limitation'
    name=chosen.Candidate; threshold=float(chosen.Threshold); pp,mm=candidates[name]
    finite = FunctionTransformer(np.nan_to_num, kw_args={'nan':np.nan,'posinf':np.nan,'neginf':np.nan}, feature_names_out='one-to-one')
    finite.set_output(transform='pandas')
    finite.fit(Xdev)
    final=Pipeline([('finite',finite)]+list(pp.steps)+[('classifier',mm)])
    pt=final.predict_proba(Xtest)[:,1]; finalmetrics=metrics(ytest,pt,threshold)
    config={'candidate':name,'threshold':threshold,'selection_dataset':'validation14','selection_rule':'Recall >= 0.95 then highest Precision; ties Recall/F1/threshold', 'selection_status':status,'validation_metrics':chosen.to_dict(),'test_metrics':finalmetrics,'feature_columns':list(X.columns),'selected_features':list(X.columns[pp.named_steps['variance'].get_support()][pp.named_steps['rfe'].support_]),'positive_label':'Bot','negative_label':'BENIGN','test_target_met':bool(finalmetrics['Recall']>=.95),'sklearn_version':sklearn_version}
    (out/'model'/'threshold.json').write_text(json.dumps(config,indent=2),encoding='utf8')
    joblib.dump(final,out/'model'/'ids_model.joblib',compress=3)
    restored=joblib.load(out/'model'/'ids_model.joblib'); assert np.allclose(pt[:20],restored.predict_proba(Xtest.iloc[:20])[:,1])
    th=sweep[sweep.Candidate==name].copy(); th.to_csv(res/'threshold_analysis.csv',index=False)
    pd.DataFrame([dict(Threshold=t,**metrics(ytest,pt,t)) for t in np.round(np.arange(.1,1,.1),2)]).to_csv(res/'test_threshold_analysis_descriptive.csv',index=False)
    plt.figure(figsize=(6,4))
    for metric in ['Precision','Recall','F1']: plt.plot(th.Threshold,th[metric],marker='o',label=metric)
    plt.axhline(.95,color='gray',ls='--',label='Recall target'); plt.axvline(threshold,color='black',ls=':'); plt.ylim(0,1.03); plt.xlabel('Threshold'); plt.title('Validation threshold selection'); plt.legend(); savefig('threshold_analysis.png')
    cm=confusion_matrix(ytest,pt>=threshold,labels=[0,1]); plt.figure(figsize=(5,4)); sns.heatmap(cm,annot=True,fmt='d',cmap='Blues',xticklabels=['NORMAL','BOT ALERT'],yticklabels=['BENIGN','Bot']); plt.xlabel('Predicted'); plt.ylabel('Actual'); plt.title('Untouched test set at selected threshold'); savefig('confusion_matrix.png')
    fpr,tpr,_=roc_curve(ytest,pt); plt.figure(figsize=(5,4)); plt.plot(fpr,tpr,label=f"AUC = {finalmetrics['ROC_AUC']:.5f}"); plt.plot([0,1],[0,1],'--',color='gray'); plt.xlabel('False positive rate'); plt.ylabel('True positive rate'); plt.legend(); savefig('roc_curve.png')
    pr,re,_=precision_recall_curve(ytest,pt); plt.figure(figsize=(5,4)); plt.plot(re,pr,label=f"AP = {finalmetrics['PR_AUC']:.4f}"); plt.axhline(ytest.mean(),ls='--',color='gray',label='Bot prevalence'); plt.xlabel('Recall'); plt.ylabel('Precision'); plt.legend(); savefig('pr_curve.png')
    importance=pd.Series(mm.feature_importances_,index=config['selected_features']).sort_values(ascending=False)
    importance.rename_axis('Feature').rename('Importance').to_csv(res/'feature_importance.csv')
    plt.figure(figsize=(8,4)); importance.head(10).sort_values().plot.barh(); plt.xlabel('Impurity importance'); plt.title('Top 10 features of selected IDS'); savefig('feature_importance.png')
    error=raw.loc[Xtest.index].copy(); error['Actual']=ytest; error['Attack_probability']=pt; error['Predicted']=(pt>=threshold).astype(int)
    fp=error[(error.Actual==0)&(error.Predicted==1)]; fn=error[(error.Actual==1)&(error.Predicted==0)]
    fp.to_csv(res/'false_positive.csv'); fn.to_csv(res/'false_negative.csv')
    # Inspect every FN if fewer than ten exist. Add separately labelled validation FN
    # and correct near-threshold Bot examples to reach ten reviewed records, never fabricate FN.
    reviewed=fn.sort_values('Attack_probability').head(10).copy(); reviewed['Review_type']='Test False Negative'
    if len(reviewed)<10:
        extra=error[(error.Actual==1)&(error.Predicted==1)].sort_values('Attack_probability').head(10-len(reviewed)).copy(); extra['Review_type']='Test True Positive near threshold (NOT FN)'; reviewed=pd.concat([reviewed,extra])
    reviewed.to_csv(res/'error_review_10_samples.csv')
    bottrain=Xdev.loc[ydev==1,config['selected_features']].median(); normaltrain=Xdev.loc[ydev==0,config['selected_features']].median()
    pd.DataFrame({'BENIGN_train_median':normaltrain,'Bot_train_median':bottrain}).rename_axis('Feature').to_csv(res/'class_feature_medians.csv')
    # A replay of held-out recorded flows, not live capture or evidence of novel attack detection.
    ids=list(ytest[ytest==0].index[:5])+list(ytest[ytest==1].index[:5])
    stream=raw.loc[ids,['Source IP','Destination IP','Destination Port','Protocol']].copy(); stream['Actual']=ytest.loc[ids]
    p=restored.predict_proba(X.loc[ids])[:,1]; stream['Attack_probability']=p; stream['Threshold']=threshold; stream['Decision']=np.where(p>=threshold,'BOT ALERT','NORMAL'); stream.to_csv(res/'streaming_inference.csv')
    (res/'eda.json').write_text(json.dumps(eda,indent=2),encoding='utf8')
    (res/'runtime.json').write_text(json.dumps({'seconds':time.time()-start,'python':platform.python_version(),'sklearn':sklearn_version,'pandas':pd.__version__,'numpy':np.__version__},indent=2))
    log('FINAL '+json.dumps(config)); log('Saved model reload and probability equivalence passed')

if __name__=='__main__':
    ap=argparse.ArgumentParser(); ap.add_argument('--csv',required=True); ap.add_argument('--output',default='CE181900_Chapter9_IDS'); a=ap.parse_args(); main(a.csv,a.output)

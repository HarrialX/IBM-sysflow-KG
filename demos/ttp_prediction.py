import os
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader
import torch.optim.lr_scheduler as lr_scheduler

from collections import defaultdict
import networkx as nx
import numpy as np
import random
import time

import dgl
from dgl import DGLGraph
import dgl.function as fn

NodeNum = -1

class ARGS:
    def __init__(self):
        self.sysflow_path = './sysflow_data'
        self.test_ratio = 0.25
        self.batch_size = 64
        self.feat_dim = 200
        self.lr = 0.001
        self.train_epochs = 100
        self.log_every = 1
        self.eval_every = 5
        self.train_verbose = True

def load_sysflow(args):
    graph_dict = defaultdict(lambda: defaultdict(set))
    """
       gid (path as str): {
           nodes: {str},
           edges: {tuple(str)}
           labels:{str}
       }
    """
    for root, _, filenames in os.walk(args.sysflow_path):
        if root.endswith('/data') :
            for filename in filenames:
                if filename.endswith('nodes'):
                    gname = os.path.join(root, filename.split('.')[0])
                    
                    # a graph-nodes file
                    nodes, labels = set(), set()
                    nid2nname = {}
                    for l in open(os.path.join(root, filename), 'r').readlines():
                        nid, nname, ttps = l.strip().split('\t')
                        nname = nname.strip("()").split(',')[0].strip("' ")
                        # nname = ' '.join([s.strip("' ") for s in nname.strip("()").split(',')[:2]])
                        nid2nname[nid] = nname
                        nodes.add(nname)
                        
                        if ttps != 'None':
                            ttps = [ttp.strip("'mitre: ") for ttp in ttps.strip('{}').split(',')]
                            ttps = [ttp for ttp in ttps if ttp.startswith('T')]
                            labels |= set(ttps)
                    
                    if len(labels) == 0:
                        continue
                    graph_dict[gname]['nodes'] = nodes
                    graph_dict[gname]['labels'] = labels
                    
                    # a graph-edges file
                    for l in open(os.path.join(root, filename.split('.')[0]+'.edges'), 'r').readlines():
                        srcnid, ename, dstnid = l.strip().split('\t')
                        srcnname = nid2nname[srcnid]
                        dstnname = nid2nname[dstnid]
                        graph_dict[gname]['edges'].add((srcnname, dstnname))

    return graph_dict
         
    
def graph_int_dict(args, graph_dict):
    gidmap = {}
    nidmap = {}
    lidmap = {}
    for gname, values in graph_dict.items():
        assert gname not in gidmap
        gidmap[gname] = len(gidmap)
        
        for nname in values['nodes']:
            if nname not in nidmap:
                nidmap[nname] = len(nidmap)
                
        for ttp in values['labels']:
            if ttp not in lidmap:
                lidmap[ttp] = len(lidmap)

    graph_dict_int = defaultdict(lambda: defaultdict(set))
    
    for gname, values in graph_dict.items():
        gid = gidmap[gname]
        
        for nname in values['nodes']:
            graph_dict_int[gid]['nodes'].add(nidmap[nname])
            
        graph_dict_int[gid]['labels'] = [0]*len(lidmap)
        for ttp in values['labels']:
            graph_dict_int[gid]['labels'][lidmap[ttp]] = 1

        for edge in values['edges']:
            if edge[0] != edge[1]:  # omit self-loop
                graph_dict_int[gid]['edges'].add((nidmap[edge[0]], nidmap[edge[1]]))
    
    print(len(gidmap), len(nidmap), len(lidmap))
    print('Average node num', sum([len(graph_dict[gid]['nodes']) for gid in graph_dict])/len(graph_dict))
    print('Average edge num', sum([len(graph_dict[gid]['edges']) for gid in graph_dict])/len(graph_dict))
    print('Average edge degree', sum([len(graph_dict[gid]['edges'])/len(graph_dict[gid]['nodes']) for gid in graph_dict])/len(graph_dict))
    global NodeNum
    NodeNum = len(nidmap)
    return graph_dict_int, (gidmap, nidmap, lidmap)



# ----------------- Inductive GCN ----------------- #

def numpy_to_graph(A,type_graph='dgl',node_features=None, to_cuda=True):
    '''Convert numpy arrays to graph
    Parameters
    ----------
    A : mxm array
        Adjacency matrix
    type_graph : str
        'dgl' or 'nx'
    node_features : dict
        Optional, dictionary with key=feature name, value=list of size m
        Allows user to specify node features
    Returns
    -------
    Graph of 'type_graph' specification
    '''
    
    G = nx.from_numpy_array(A)
    
    if node_features != None:
        for n in G.nodes():
            for k,v in node_features.items():
                G.nodes[n][k] = v[n]
    
    if type_graph == 'nx':
        return G
    
    G = G.to_directed()
    
    if node_features != None:
        node_attrs = list(node_features.keys())
    else:
        node_attrs = []
        
    g = dgl.from_networkx(G, node_attrs=node_attrs, edge_attrs=['weight'])
    if to_cuda:
        g = g.to(torch.device('cuda'))
    return g

gcn_msg = fn.copy_src(src='h', out='m')
gcn_reduce = fn.sum(msg='m', out='h')


# Used for inductive case (graph classification) by default.
class GCNLayer(nn.Module):
    def __init__(self, in_feats, out_feats):
        super(GCNLayer, self).__init__()
        self.linear = nn.Linear(in_feats, out_feats)

    def forward(self, g, feature):
        # Creating a local scope so that all the stored ndata and edata
        # (such as the `'h'` ndata below) are automatically popped out
        # when the scope exits.
        with g.local_scope():
            g.ndata['h'] = feature
            g.update_all(gcn_msg, gcn_reduce)
            h = g.ndata['h']
            return self.linear(h)


# 2 layers by default
class GCN(nn.Module):
    def __init__(self, 
                 in_dim, 
                 out_dim,
                 hidden_dim=[128, 64, 32],  # GNN layers + 1 layer MLP
                 dropout=0.2,
                 n_fc_layer=2,
                 activation=F.relu):
        super(GCN, self).__init__()
        self.embeddings = nn.Embedding(NodeNum+1, in_dim) # last row is dummy
        self.layers = nn.ModuleList()

        self.layers.append(GCNLayer(in_dim, hidden_dim[0]))
        for i in range(len(hidden_dim) - 1):
            self.layers.append(GCNLayer(hidden_dim[i], hidden_dim[i+1]))
    
        fc = []
        if dropout > 0:
            fc.append(nn.Dropout(p=dropout))
        for _ in range(n_fc_layer-1):
            fc.append(nn.Linear(hidden_dim[-1], hidden_dim[-1]))
            if dropout > 0:
                fc.append(nn.Dropout(p=dropout))
        fc.append(nn.Linear(hidden_dim[-1], out_dim))
        self.activation = activation
        self.fc = nn.Sequential(*fc)


    def forward(self, data):
        batch_g = []
        for adj in data[1]:
            batch_g.append(numpy_to_graph(adj.cpu().detach().T.numpy(), to_cuda=adj.is_cuda)) 
        batch_g = dgl.batch(batch_g)
        
        mask = data[2]
        if len(mask.shape) == 2:
            mask = mask.unsqueeze(2) # (B,N,1)  
        
        B,N = data[0].shape[:2]
        F = self.embeddings.weight.shape[1]
        x = self.embeddings(data[0])
        x = x.reshape(B*N, F)
        mask = mask.reshape(B*N, 1)
        for layer in self.layers:
            x = layer(batch_g, x)
            x = x * mask
        
        F_prime = x.shape[-1]
        x = x.reshape(B, N, F_prime)
        x = torch.max(x, dim=1)[0].squeeze()  # max pooling over nodes (usually performs better than average)
        # x = torch.mean(x, dim=1).squeeze()
        x = self.fc(x)
        if self.activation:
            # x = self.activation(x, dim=-1)
            x = self.activation(x)
        return x
    

class GraphData(torch.utils.data.Dataset):
    def __init__(self, graph_dict, idmaps, gids):
        self.n_node_max = max([len(graph_dict[gid]['nodes']) for gid in gids])
        self.num_classes = len(idmaps[2])
        self.labels = [graph_dict[gid]['labels'] for gid in gids]
        self.adj_list = [self.get_adj(graph_dict[gid]['nodes'], graph_dict[gid]['edges']) for gid in gids]
        self.nid_list = [list(graph_dict[gid]['nodes']) for gid in gids]

    def get_adj(self, nids, edges):
        nid_map = {}
        for nid in nids:
            nid_map[nid] = len(nid_map)
        
        adj = torch.zeros(len(nid_map), len(nid_map))
        for src_nid, dst_nid in edges:
            adj[nid_map[src_nid]][nid_map[dst_nid]] = 1

        return adj

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, index):
        # convert to torch
        return [torch.as_tensor(self.nid_list[index], dtype=torch.long),  # nodes
                torch.as_tensor(self.adj_list[index], dtype=torch.float),  # adj matrices
                torch.as_tensor(self.labels[index], dtype=torch.float)]


def collate_batch(batch):
    '''
    function: Creates a batch of same size graphs by zero-padding node features and adjacency matrices 
            up to the maximum number of nodes in the CURRENT batch rather than in the entire dataset.
    param batch: [node_features*batch_size, A*batch_size, label*batch_size]
    return: [padded feature matrices, padded adjecency matrices, non-padding positions, nodenums, labels]
    '''
    B = len(batch)
    nodenums = [len(batch[b][1]) for b in range(B)]
    n_node_max = int(np.max(nodenums))  # within this batch

    graph_support = torch.zeros(B, n_node_max)
    A = torch.zeros(B, n_node_max, n_node_max)
    nids = torch.zeros(B, n_node_max).fill_(NodeNum).long() # dummy nid
    for b in range(B):
        nids[b, :nodenums[b]] = batch[b][0]                # store original values in top (no need to pad feat dim, node dim only)
        A[b, :nodenums[b], :nodenums[b]] = batch[b][1]   # store original values in top-left corner
        graph_support[b][:nodenums[b]] = 1  # mask with values of 0 for dummy (zero padded) nodes, otherwise 1

    nodenums = torch.from_numpy(np.array(nodenums)).long()
    labels = torch.stack([batch[b][2] for b in range(B)])
    return [nids, A, graph_support, nodenums, labels]

    
    # Note: here mask "graph_support" is only a 1D mask for each graph instance.
    #       When use this mask for 2D work, should first extend into 2D.
    

    
def run(args):
    assert torch.cuda.is_available(), 'no GPU available'
    cpu = torch.device('cpu')
    # cuda = torch.device('cuda')
    cuda = "cpu"

    # load data 
    graph_dict = load_sysflow(args)
    graph_dict, idmaps = graph_int_dict(args, graph_dict)   
    test_gids = random.sample(list(graph_dict.keys()), int(len(graph_dict)*args.test_ratio))
    train_gids = list(set(graph_dict.keys())-set(test_gids))

    loaders = {}
    for subset in ['train', 'test']:
        if subset == 'train':
            gdata = GraphData(graph_dict, idmaps, train_gids)
        else:
            gdata = GraphData(graph_dict, idmaps, test_gids)
        loader = DataLoader(gdata,
                            batch_size=args.batch_size,
                            shuffle=False,
                            collate_fn=collate_batch)
        # data in loaders['train/test'] is saved as returned format of collate_batch()
        loaders[subset] = loader
    print('train %d, test %d' % (len(loaders['train'].dataset), len(loaders['test'].dataset)))

    # prepare model
    in_dim = args.feat_dim
    out_dim = loaders['train'].dataset.num_classes
    # model = GCN(in_dim, out_dim, activation=F.softmax)
    model = GCN(in_dim, out_dim, activation=torch.sigmoid)
    # print(model) 

    train_params = list(filter(lambda p: p.requires_grad, model.parameters()))

    # training
    # loss_fn = F.binary_cross_entropy_with_logits
    loss_fn = F.binary_cross_entropy
    optimizer = torch.optim.Adam(train_params, lr=args.lr, betas=(0.5, 0.999))
    # scheduler = lr_scheduler.MultiStepLR(optimizer, args.lr_decay_steps, gamma=0.1)
    
    model.to(cuda)
    train_accs = []
    for epoch in range(args.train_epochs):
        model.train()
        start = time.time()
        train_loss, correct, n_samples = 0, 0, 0
        for batch_id, data in enumerate(loaders['train']):
            for i in range(len(data)):
                data[i] = data[i].to(cuda)
            optimizer.zero_grad()
            output = model(data)
            if len(output.shape)==1:
                output = output.unsqueeze(0) 

            # output shape [B, labels_num]
            loss = loss_fn(output, data[4])
            loss.backward()
            optimizer.step()
            # scheduler.step()

            time_iter = time.time() - start
            train_loss += loss.item() * len(output)
            n_samples += len(output)

            B, C = output.shape 
            for b in range(B):
                ground_label = [i for i in range(C) if data[4][b][i] == 1]
                pred_label = torch.argsort(-output[b])[:len(ground_label)].tolist()
                correct += len(set(ground_label) & set(pred_label)) / len(ground_label)

        train_acc = 100 * correct / n_samples
        train_accs.append(train_acc)
        if args.train_verbose and (epoch % args.log_every == 0 or epoch == args.train_epochs - 1):
            print('Train Epoch: %d\tLoss: %.4f (avg: %.4f) \tAccuracy: %d/%d (%.2f%s) \tsec/iter: %.2f' % (
                epoch + 1, loss.item(), train_loss / n_samples, correct, n_samples, train_acc, '%', time_iter / (batch_id + 1)))

        if (epoch + 1) % args.eval_every == 0 or epoch == args.train_epochs-1:
            model.eval()
            start = time.time()
            test_loss, correct, n_samples = 0, 0, 0
            for batch_id, data in enumerate(loaders['test']):
                for i in range(len(data)):
                    data[i] = data[i].to(cuda)
                # if args.use_org_node_attr:
                #     data[0] = norm_features(data[0])
                output = model(data)
                if len(output.shape)==1:
                    output = output.unsqueeze(0)
                loss = loss_fn(output, data[4], reduction='sum')
                test_loss += loss.item()
                n_samples += len(output)
                
                # # single label
                # pred = predict_fn(output)
                # correct += pred.eq(data[4].detach().cpu().view_as(pred)).sum().item()

                # multi label
                B, C = output.shape 
                for b in range(B):
                    ground_label = [i for i in range(C) if data[4][b][i] == 1]
                    pred_label = torch.argsort(-output[b])[:len(ground_label)].tolist()
                    correct += len(set(ground_label) & set(pred_label)) / len(ground_label)
                    # print(ground_label, pred_label)
            eval_acc = 100. * correct / n_samples
            print('Test set (epoch %d): Average loss: %.4f, Accuracy: %f/%d (%.2f%s) \tsec/iter: %.2f' % (
                epoch + 1, test_loss / n_samples, correct, n_samples, 
                eval_acc, '%', (time.time() - start) / len(loaders['test'])))

    model.to(cpu)
    print(train_accs)

    # return model


run(ARGS())
// Solitaire core game logic

var game,can,spr,bw,bh;
var done=0;
var mx,my;// current pointer location
var gx,gy;// grabbed square
var fx=fy=-1;// mouse grabbed coords
var px,py,pz;// phone/touch grabbed
var drag=0; //draggable
var xx=7; //cards across
var yy=25; //vertical sections
var cs=5; //card grid length
var sprd=[]; // main area
var flow=[]; // dragged cards
var aces=[[],[],[],[]]; // aces storage
var flox=[];var floy=[];
var flod=0;
var flower;
var bgsk;
co1='lime';co2='green';drw=1;fre=1;

function initSolitaire() {
    var drwEl = document.getElementById("soldrw");
    if (drwEl) {
        drwEl.onchange = function(){ drw=this.value*1; };
    }
    var freEl = document.getElementById("solfre");
    if (freEl) {
        freEl.onchange = function(){ fre=this.value*1; };
    }
    var co1El = document.getElementById("co1");
    if (co1El) {
        co1El.onchange = function(){ co1=this.value; redraw(); };
    }
    var co2El = document.getElementById("co2");
    if (co2El) {
        co2El.onchange = function(){ co2=this.value; redraw(); };
    }
    var togEl = document.getElementById("soltogsetup");
    if (togEl) {
        togEl.onclick = function(){
            var soltog=document.getElementById("solsetup");
            if (soltog.style.display !== "none") {
                soltog.style.display = "none";
            } else {
                soltog.style.display = "block";
            }
        };
    }
    var startEl = document.getElementById("solstart");
    if (startEl) {
        startEl.onclick = function(){
            done=0;
            aces=[[],[],[],[]];
            start();
        };
    }
    start();
}

window.addEventListener('load', initSolitaire);

function flowdn(){
 if (flod<1){return;}
 flod--;
 flox.pop();floy.pop();
 flox.reverse();floy.reverse();
 flox.push(mx-(tmpw/2));
 floy.push(my);
 flox.reverse();floy.reverse();
 clrcan(spr);
 for (i=0;i<flow.length;i++){
   dcd(spr,flox[i],floy[i]+((bw/yy)*i),flow[i],tmpw,co1,co2);
 }
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function clku(evn){
 evn.stopPropagation();
 evn.preventDefault();
 clearInterval(flower);
 clrcan(spr);
 if (done) { return; }

 if (evn.changedTouches){
  var rect = can.getBoundingClientRect();
  mx=Math.floor(evn.changedTouches[0].clientX-rect.left);
  my=Math.floor(evn.changedTouches[0].clientY-rect.top);
 }
 tx=Math.floor((mx/bw)*xx); ty=Math.floor((my/bh)*yy);

 if (flow.length<1 && tx==0 && ty>=1 && ty<=4){
  tmpw=bw/xxx;
  ccc=dr(drw);

  if (ccc.length>0) {
   pile.push(...ccc);
   for (ii=0;ii<drw-1;ii++){
    dcd(can,(1*(tmpw+(tmpw/xxx)))+(tmpw/xxx),(bw/yy)*(1),ccc[ii],tmpw,co1,co2);
    await sleep(300);
   }
  }else{
   deck=pile;
   deck.reverse();
   pile=[];
   tc='';
  }
  tc=pile[pile.length-1];
 } else if (drag){
  ffx=Math.floor((fx/bw)*xx); ffy=Math.floor((fy/bh)*yy);

  if (ty<5 && tx>2){
   dbtc=aces[tx-3][aces[tx-3].length-1];
  }else{
   dbtc=sprd[tx][sprd[tx].length-1];
  }
  cvz=[ crdval(flow[0],0), crdval(dbtc,0) ];
  cvz.push( crdcol(flow[0],dbtc) );

  if (ffy>5){
   var tmp=undefined;
   for (i=0;i<(cs);i++){
    tmp= tmp===undefined ? sprd[ffx][ffy-6-i] : tmp;
    if (tmp!=undefined) break;
   }
  }

  if (flow.length==1 && ty<6 && tx>2 && tx<7){
   fail=0;
   if (flow[0][0]!=sc[tx-3]){
    fail= !fre ? 0 : 1;
   }
   if (cvz[0]!=cvz[1]+1){
     fail= !fre || (cvz[0]==0 && cvz[1]==-1) ? fail : 1;
   }

   if (fail>0){
    if (ffy<5 && ffx<3){
     pile.push(flow[0]);
    } else if (ffy<5 && ffx>2){
     (aces[ffx-3]).push(flow[0]);
    }else{
     sprd[ffx].push(...flow);
    }
   }else{
    (aces[tx-3]).push(flow[0]);
    flp=0;
   }
  }else if(flow.length && ty>5){
   if (flow[0]!=undefined){
    fail=0;
    if (cvz[2] && cvz[2][3]==true) {
     fail= !fre ? 0 : 1;
    }
    if (cvz[0]!=cvz[1]-1 && cvz[1]!=-1) {
     fail= !fre ? 0 : 1;
    }

    if (fail){
     if (ffy>5){
      sprd[ffx].push(...flow);
     }else if (ffx>2 && ffx<7){
      (aces[ffx-3]).push(flow[0]);
     } else {
      pile.push(flow[0]);
     }
    }else{
     sprd[tx].push(...flow);
    }
   }
   var flp= tx==ffx ? 1:0;
  }else{
   if (flow[0]){
    if (ffy>5){
     sprd[ffx].push(...flow);
    }else if (ffx>2 && ffx<7){
     (aces[ffx-3]).push(flow[0]);
    }else{
     pile.push(flow[0]);
    }
   }
  }
  clrcan(can);
 }
 drag=0;fx=-1;fy=-1;
 redraw(flp);
 flow=[];
 tc="";

 if (aces[0].length>12 && aces[1].length>12 && aces[2].length>12 && aces[3].length>12){
   done=1;
   dnm(spr,(bw/4),(bh/3),25,"Congrats, Game Over!",1);
  }
}

function getCoords(evn) {
 var rect = spr.getBoundingClientRect();
 var clientX = evn.clientX;
 var clientY = evn.clientY;
 if (evn.changedTouches && evn.changedTouches.length > 0) {
  clientX = evn.changedTouches[0].clientX;
  clientY = evn.changedTouches[0].clientY;
 } else if (evn.touches && evn.touches.length > 0) {
  clientX = evn.touches[0].clientX;
  clientY = evn.touches[0].clientY;
 }
 return {
  x: Math.floor((clientX - rect.left) * (bw / rect.width)),
  y: Math.floor((clientY - rect.top) * (bh / rect.height))
 };
}

function clkd(evn){
 if (flow.length) { return; }
 flox=[];floy=[];
 clrcan(can);
 redraw(1);
 bgsk=0;
 if (done) { return; }
 var coords = getCoords(evn);
 mx = coords.x;
 my = coords.y;
 fx=mx;fy=my;
 gx=Math.floor((mx/bw)*xx); gy=Math.floor((my/bh)*yy);
 if (gy>5 && sprd[gx][gy-6] && sprd[gx][gy-6].substr(0,1)=='x'){
  fx=-1;fy=-1;gx=-1;gy=-1;
 }
}

function movr(evn){
 if (done) { return; }
 var coords = getCoords(evn);
 mx = coords.x;
 my = coords.y;

 if (fx==-1){ return; }
 drag=1;
 tmpw=bw/xxx;
 tx=Math.floor((fx/bw)*xx); ty=Math.floor((fy/bh)*yy);
 if (tx>-1){
  if (!tc){
   var tc=undefined;
   if (gy<5 && gx==1){
    tc=pile[pile.length-1];
   } else {
    for (i=0;i<(cs);i++){
     tc= tc===undefined ? sprd[tx][ty-6-i] : tc;
     if (tc!=undefined) break;
    }
   }
  }

  if (!flow[0]) {
   if (gy<5 && gx>2 && gx<7 && aces[gx-3]!=undefined){
    flow[0]=aces[gx-3].pop();
   }
   if (gy<5 && gx==1){
    if (pile.length>0){
     flow[0]=pile.pop();
    }else{
     fx=-1;
    }
  } else {
   i=0;
   var tmpz;
   while (tmpz!=tc){
    var tmpz=sprd[tx].pop();
    if (tmpz){
     flow[i]=tmpz;
     flox[i]=mx-(tmpw/2);
     floy[i]=my+((bw/yy)*i);
     i++;
    }
   }
   flow.reverse();
   flox.reverse();
   floy.reverse();
 }
   if (flow[0]==undefined){
    flow=[];
   }
  } else {
   if (flow.length){
    flox.pop();floy.pop();
    flox.unshift(mx-(tmpw/2));
    floy.unshift(my);
    clearInterval(flower);
    flower=setInterval(flowdn,60);
   }
  }

  clrcan(spr);
  for (i=0;i<flow.length;i++){
   dcd(spr,flox[i],floy[i]+((bw/yy)*i),flow[i],tmpw,co1,co2);
  }
  flod=i;
  }
  if (!bgsk) {
   clrcan(can);
   redraw(1);
   bgsk=1;
  }
}

function redraw(flip=0) {
 xxx=xx+1;
 var tmpw=bw/xxx;
 for (ii=0;ii<7;ii++) {
  if (ii!=2) {
   var tc='';
   if (ii==0){
    tc=deck.length>0 ? 'b1' : '';
   }
   if (ii==1){
    tc=pile.length>0 ? pile[pile.length-1] : '';
   }
   if (ii==3){
    tmp=aces[0].length;
    tc=tmp ? aces[0][tmp-1] : 'c';
   }
   if (ii==4){
    tmp=aces[1].length;
    tc=tmp ? aces[1][tmp-1] : 't';
   }
   if (ii==5){
    tmp=aces[2].length;
    tc=tmp ? aces[2][tmp-1] : 's';
   }
   if (ii==6){
    tmp=aces[3].length;
    tc=tmp ? aces[3][tmp-1] : 'd';
   }
   dcd(can,(ii*(tmpw+(tmpw/xxx)))+(tmpw/xxx),(bw/yy),tc,tmpw,co1,co2);
  }
 }
 for (ii=0;ii<7;ii++) {
  var tmp=[];
  for (i=0;i<sprd[ii].length;i++) {
   var crd=sprd[ii][i];
   if (crd){
    if (flip==0 && crd.substr(0,1)=='x' && i==sprd[ii].length-1){
     sprd[ii][i]=crd.substr(1,2);
     crd=sprd[ii][i];
    }
    crd=crd.substr(0,1)=='x' ? 'b1' : crd;
    dcd(can,(ii*(tmpw+(tmpw/xxx)))+(tmpw/xxx),(bw/yy)*(i+6),crd,tmpw,co1,co2);
   }
  }
 }
 return;
}

function start(){
 game = document.getElementById('game') || document.body;
 var w = game.clientWidth || window.innerWidth || 800;
 var h = game.clientHeight || window.innerHeight || 600;
 bw = Math.max(320, Math.min(w * 0.9, 600));
 bh = bw;
 can = document.getElementById('can');
 if (!can) return;
 can.width = bw; can.height = bh;
 spr = document.getElementById('spr');
 if (!spr) return;
 spr.width = bw; spr.height = bh;
 shf();
 for (ii=0;ii<7;ii++) {
  var tmp=[];
  for (i=0;i<=ii;i++) {
   tc=dr(1)[0];
   tmp[i]= ii==i ? tc : 'x'+tc;
  }
  sprd[ii]=tmp;
 }

 redraw();
 spr.onmousedown = clkd;
 spr.onmouseup = clku;
 spr.onmousemove = movr;
 spr.oncontextmenu = function(e) { e.preventDefault(); return false; };
 spr.addEventListener("touchstart", clkd, {passive: true});
 spr.addEventListener("touchend", clku, false);
 spr.addEventListener("touchmove", movr, {passive: true});
}

/**
 * Generates a puzzle based on the provided options.
 * @param {object} options - The settings for the puzzle generation.
 * @returns {object} The generated puzzle data.
 */
function generatePuzzle(options) {
    // Default options, mimicking the original PHP defaults.
    const defaults = {
        wdh: 4, hgt: 4, mov: 2, rot: 1, clr: 5, pct: 55, pnt: -1, rat: 0
    };
    const settings = { ...defaults, ...options };

    let { wdh, hgt, mov, rot, clr, pct, pnt } = settings;

    // --- Ensure numeric types, as values from HTML inputs are strings ---
    mov = parseInt(mov, 10);
    rot = parseInt(rot, 10);
    clr = parseInt(clr, 10);
    pct = parseInt(pct, 10);
    pnt = parseInt(pnt, 10);

    // --- Parameter Validation ---
    // Ensures the settings are within the allowed ranges.
    if (wdh < 3 || wdh > 40) { wdh = 4; }
    if (hgt < 3 || hgt > 40) { hgt = 4; }
    if (mov < 2 || mov > 4) { mov = 2; }
    if (rot < 0 || rot > 3) { rot = 1; }
    if (clr < 2 || clr > 9) { clr = 3; }
    if (pct < 20 || pct > 80) { pct = 55; }
    if (pnt < 0 || pnt > 9) { pnt = -1; }

    const maxx = [0, 1, 2, 1, 2, 1, 1, 1, 0];
    const colStr = 'grybvcplei';
    const col = colStr.substring(0, clr + 1);
    const xx = parseInt(wdh);
    const yy = parseInt(hgt);

    let grid = Array(xx).fill(null).map(() => Array(yy).fill('000000'));

    // --- 1. Generate the Solved Path ---
    // This section creates a random path of pieces, ensuring they are all connected.
    // At this stage, the colors are internally consistent along the path.

    // Create a random starting position.
    let sx = Math.floor(Math.random() * xx);
    let sy = Math.floor(Math.random() * yy);

    // Initial piece properties.
    let current_mo = '2'; // move type
    let current_ro = '0'; // rotation type

    // Generate initial color tags for the starting piece.
    // These are random for now and will be cleaned up later if they border empty space.
    let sc = '';
    sc += sx > 0 ? col.charAt(Math.floor(Math.random() * (col.length - 1)) + 1) : '0'; // L
    sc += sy > 0 ? col.charAt(Math.floor(Math.random() * (col.length - 1)) + 1) : '0'; // U
    sc += sx < xx - 1 ? col.charAt(Math.floor(Math.random() * (col.length - 1)) + 1) : '0'; // R
    sc += sy < yy - 1 ? col.charAt(Math.floor(Math.random() * (col.length - 1)) + 1) : '0'; // D

    grid[sx][sy] = current_mo + current_ro + sc;

    let unsort = [current_mo + current_ro + '-' + sx + '-' + sy];
    let rew = [[sx], [sy]]; // Keep track of coordinates for the rewind logic.

    let max_fixed_points;
    if (pnt === -1) {
        max_fixed_points = (xx < maxx.length) ? maxx[xx] : 0;
    } else {
        max_fixed_points = pnt;
    }

    let fixed_points_count = 0;
    const path_length = (xx * yy) * (pct / 100);

    for (let i = 1; i < path_length; i++) {
        let possible_moves = posmov(sx, sy, xx, yy, grid);

        // If the path generation gets stuck (0 moves), we need to rewind and find a new place to branch from.
        // The original PHP logic was a bit unusual: it would keep rewinding as long as the new spot had 0 OR 4 possible moves.
        if (possible_moves.length === 0) {
            let attempts = 0;
            // Keep trying to find a better spot on the path to branch from.
            while ((possible_moves.length === 0 || possible_moves.length === 4) && attempts < 50) {
                if (rew[0].length < 3) { break; } // Not enough path to rewind.
                // Pick a random, previous point on the path (but not the start or the absolute end).
                const rewind_index = Math.floor(Math.random() * (rew[0].length - 2)) + 1;
                sx = rew[0][rewind_index];
                sy = rew[1][rewind_index];
                possible_moves = posmov(sx, sy, xx, yy, grid);
                attempts++;
            }
        }

        // If, after trying to rewind, we're still stuck or have no valid moves, skip this iteration.
        if (possible_moves.length === 0) {
            continue;
        }

        const move = possible_moves.charAt(Math.floor(Math.random() * possible_moves.length));

        if (fixed_points_count < max_fixed_points) {
            current_mo = (Math.floor(Math.random() * mov) + 1).toString();
        } else {
            current_mo = (Math.floor(Math.random() * (mov - 1)) + 2).toString();
        }
        if (current_mo === '1') {
            fixed_points_count++;
        }
        current_ro = (Math.floor(Math.random() * (rot + 1))).toString();

        // Move to the new position
        if (move === 'L') { sx--; }
        if (move === 'U') { sy--; }
        if (move === 'R') { sx++; }
        if (move === 'D') { sy++; }

        rew[0].push(sx);
        rew[1].push(sy);
        grid[sx][sy] = current_mo + current_ro + gentag(sx, sy, xx, yy, grid, col);
        unsort.push(current_mo + current_ro + '-' + sx + '-' + sy);
    }

    // --- 2. Clear Unmatched Edges ---
    // This is the critical step to ensure solvability. It iterates over all EMPTY
    // cells and clears the color tags of any adjacent pieces that point towards
    // the empty cell. This guarantees that every colored edge has a matching pair.
    // This version is a direct, literal translation of the original PHP.
    let empty = [];
    for (let y = 0; y < yy; y++) {
        for (let x = 0; x < xx; x++) {
            if (grid[x][y].substring(0, 1) === '0') {
                empty.push(x + 'x' + y);
                let neighbors = fdwall(x, y, xx, yy);

                // Neighbor Below (D) exists, so clear its UP tag.
                if (neighbors.includes('D')) {
                    const s = grid[x][y + 1];
                    grid[x][y + 1] = s.substring(0, 3) + '0' + s.substring(4);
                }
                // Neighbor Above (U) exists, so clear its DOWN tag.
                if (neighbors.includes('U')) {
                    const s = grid[x][y - 1];
                    grid[x][y - 1] = s.substring(0, 5) + '0';
                }
                // Neighbor Left (L) exists, so clear its RIGHT tag.
                if (neighbors.includes('L')) {
                    const s = grid[x - 1][y];
                    grid[x - 1][y] = s.substring(0, 4) + '0' + s.substring(5);
                }
                // Neighbor Right (R) exists, so clear its LEFT tag.
                if (neighbors.includes('R')) {
                    const s = grid[x + 1][y];
                    grid[x + 1][y] = s.substring(0, 2) + '0' + s.substring(3);
                }
            }
        }
    }

    // --- 3. Fixup Rotations ---
    // If a piece has a flip-type rotation but its opposite sides are the same,
    // it can't be flipped. Change it to a simple rotation piece.
    for (let y = 0; y < yy; y++) {
        for (let x = 0; x < xx; x++) {
            if (grid[x][y].substring(1, 2) === '2') { // Flip U/D
                if (grid[x][y].substring(3, 4) === grid[x][y].substring(5, 6)) {
                    grid[x][y] = grid[x][y].substring(0, 1) + '1' + grid[x][y].substring(2);
                }
            }
            if (grid[x][y].substring(1, 2) === '3') { // Flip L/R
                if (grid[x][y].substring(2, 3) === grid[x][y].substring(4, 5)) {
                    grid[x][y] = grid[x][y].substring(0, 1) + '1' + grid[x][y].substring(2);
                }
            }
        }
    }

    // --- 4. Scramble the Puzzle ---
    // The puzzle is now internally consistent and solvable. This section shuffles
    // the pieces and their rotations/flips to create the final challenge.
    unsort.sort();

    for (const item of unsort) {
        const parts = item.split('-');
        const [x, y] = [parseInt(parts[1]), parseInt(parts[2])];
        let piece = grid[x][y];

        // ROTATE/FLIP the piece randomly based on its type.
        const rotType = piece.substring(1, 2);
        if (rotType === '1') { // Rotate
            for (let i = 0; i < Math.floor(Math.random() * 4); i++) {
                piece = grid[x][y];
                grid[x][y] = piece.substring(0, 2) + piece.charAt(3) + piece.charAt(4) + piece.charAt(5) + piece.charAt(2);
            }
        }
        if (rotType === '2') { // Flip UD
            if (Math.random() > 0.5) {
                piece = grid[x][y];
                grid[x][y] = piece.substring(0, 3) + piece.charAt(5) + piece.charAt(4) + piece.charAt(3);
            }
        }
        if (rotType === '3') { // Flip LR
            if (Math.random() > 0.5) {
                piece = grid[x][y];
                grid[x][y] = piece.substring(0, 2) + piece.charAt(4) + piece.charAt(3) + piece.charAt(2) + piece.charAt(5);
            }
        }

        // SCRAMBLE piece positions by swapping with empty tiles.
        const moveType = parts[0].substring(0, 1);
        if (moveType === '2') { // Move anywhere
            if (empty.length > 0) {
                const rnd = Math.floor(Math.random() * empty.length);
                const [ex, ey] = empty[rnd].split('x');
                grid[ex][ey] = grid[x][y];
                grid[x][y] = '000000';
                empty[rnd] = x + 'x' + y;
            }
        } else if (moveType === '3') { // Move UD
            const sameCol = empty.map((e, i) => e.startsWith(x + 'x') ? i : -1).filter(i => i !== -1);
            if (sameCol.length > 0) {
                const rnd_idx = sameCol[Math.floor(Math.random() * sameCol.length)];
                const [ex, ey] = empty[rnd_idx].split('x');
                grid[ex][ey] = grid[x][y];
                grid[x][y] = '000000';
                empty[rnd_idx] = x + 'x' + y;
            }
        } else if (moveType === '4') { // Move LR
            const sameRow = empty.map((e, i) => e.endsWith('x' + y) ? i : -1).filter(i => i !== -1);
            if (sameRow.length > 0) {
                const rnd_idx = sameRow[Math.floor(Math.random() * sameRow.length)];
                const [ex, ey] = empty[rnd_idx].split('x');
                grid[ex][ey] = grid[x][y];
                grid[x][y] = '000000';
                empty[rnd_idx] = x + 'x' + y;
            }
        }
    }

    // --- 5. Final Output ---
    const out = { col: col, xx: xx, yy: yy, grid: {} };
    for (let y = 0; y < yy; y++) {
        for (let x = 0; x < xx; x++) {
            out.grid[`grid[${x}][${y}]`] = grid[x][y];
        }
    }
    return out;
}


// --- Helper Functions (Direct translations from PHP) ---

/**
 * Generates the 4 color tags for a new piece based on its neighbors.
 * If a neighbor is a piece, it copies the color to match.
 * If a neighbor is empty, it assigns a random color (which gets cleaned up later).
 */
function gentag(px, py, xx, yy, grid, col) {
    let fp = '';
    // Left: Check left neighbor, copy its RIGHT tag (index 4)
    fp += (px > 0) ? (grid[px - 1][py].startsWith('0') ? col.charAt(Math.floor(Math.random() * (col.length - 1)) + 1) : grid[px - 1][py].charAt(4)) : '0';
    // Up: Check upper neighbor, copy its DOWN tag (index 5)
    fp += (py > 0) ? (grid[px][py - 1].startsWith('0') ? col.charAt(Math.floor(Math.random() * (col.length - 1)) + 1) : grid[px][py - 1].charAt(5)) : '0';
    // Right: Check right neighbor, copy its LEFT tag (index 2)
    fp += (px < xx - 1) ? (grid[px + 1][py].startsWith('0') ? col.charAt(Math.floor(Math.random() * (col.length - 1)) + 1) : grid[px + 1][py].charAt(2)) : '0';
    // Down: Check lower neighbor, copy its UP tag (index 3)
    fp += (py < yy - 1) ? (grid[px][py + 1].startsWith('0') ? col.charAt(Math.floor(Math.random() * (col.length - 1)) + 1) : grid[px][py + 1].charAt(3)) : '0';
    return fp;
}

/**
 * Finds possible empty adjacent cells to move to.
 */
function posmov(px, py, xx, yy, grid) {
    let fp = '';
    if (px > 0 && grid[px - 1][py].startsWith('0')) fp += 'L';
    if (py > 0 && grid[px][py - 1].startsWith('0')) fp += 'U';
    if (px < xx - 1 && grid[px + 1][py].startsWith('0')) fp += 'R';
    if (py < yy - 1 && grid[px][py + 1].startsWith('0')) fp += 'D';
    return fp;
}

/**
 * Finds adjacent grid cells, regardless of whether they are empty or not.
 */
function fdwall(px, py, xx, yy) {
    let fp = '';
    if (px > 0) fp += 'L';
    if (py > 0) fp += 'U';
    if (px < xx - 1) fp += 'R';
    if (py < yy - 1) fp += 'D';
    return fp;
}


//  Rest of the code continues here...

//console.log('circJS');
const col='grybvcplei';
const nxc=0; // nextcloud or normal webserver?
const compression = true; // enables compression
const scal=.95;
const hdr=document.getElementById('hdr');
const wrp=document.getElementById('wrp');
const can=document.getElementById('can');
const spr=document.getElementById('spr');
var dbtm,dbug,fo,rstim;
var fc= new Date(); //for cookie?
var done=0;
var mx,my;// current pointer location
var gx,gy;// grabbed square
var fx,fy;// mouse grabbed coords
var px,py,pz;// phone/touch grabbed
var drag='n'; //draggable
var xx,yy,grid,ww,hh,sz,xxx,yyy,outt; //from json
//const colr='grybvcplei';
let lvl=['',' 32091550',' 42152550',' 54141551',' 64332551',' 74341551',' 84351601',' 94360701','154340801'];

function compress(str) {
    if (!compression) return str;
    return str.replace(/(.)\1{2,5}/g, (match, char) => {
        const symbols = ['@', '#', '$', '%'];
        return char + symbols[match.length - 3];
    });
}

function decompress(str) {
   if (!str) return "";
   return str.replace(/(.)([@#$%])/g, (match, char, symbol) => {
        const symbols = ['@', '#', '$', '%'];
        return char.repeat(symbols.indexOf(symbol) + 3);
    });
}

document.getElementById("wxh").onchange = function(){ ttf(); saveSettings(); }
document.getElementById("rat").onchange = function(){ ttf(); saveSettings(); }
document.getElementById("mov").onchange = saveSettings;
document.getElementById("rot").onchange = saveSettings;
document.getElementById("clr").onchange = saveSettings;
document.getElementById("pnt").onchange = saveSettings;
document.getElementById("pct").onchange = saveSettings;
document.getElementById("sgcirc").onclick = function(){ sav('save original game to play from start?') }
document.getElementById("spcirc").onclick = function(){ sav('save your progress to play later?',1) }
document.getElementById("ldcirc").onclick = function(){ openFileDialog('.dbs',loadr) }
document.getElementById("circstart").onclick = function(){ wipe(true); }
document.getElementById("circstart2").onclick = function(){ wipe(true); }
window.addEventListener('resize', function(event) { rstim=setTimeout(scale,150); }, true);

document.getElementById("circtogsetup").onclick = function(){
 var cirtog=document.getElementById("circsetup");
 if (cirtog.style.display !== "none") { cirtog.style.display = "none"; }
 else {  cirtog.style.display = "block"; }
}
document.getElementById("circtoghelp").onclick = function(){
 var cirtog=document.getElementById("circhelp");
 if (cirtog.style.display !== "none") { cirtog.style.display = "none"; }
 else {  cirtog.style.display = "block"; }
}
for (var tmp=1;tmp<9;tmp++){
 document.getElementById("v"+tmp).onclick = function(e){ butt(e.target.id.replace("v", "")); }
}
loadSettings();
loadGame();

function saveSettings() {
    const settings = {
        wxh: document.getElementById('wxh').value,
        mov: document.getElementById('mov').value,
        rot: document.getElementById('rot').value,
        clr: document.getElementById('clr').value,
        pnt: document.getElementById('pnt').value,
        pct: document.getElementById('pct').value,
        rat: document.getElementById('rat').value
    };
    sStore('settings', JSON.stringify(settings));
}

function loadSettings() {
    const settings = JSON.parse(gStore('settings'));
    if (settings) {
        document.getElementById('wxh').value = settings.wxh;
        document.getElementById('mov').value = settings.mov;
        document.getElementById('rot').value = settings.rot;
        document.getElementById('clr').value = settings.clr;
        document.getElementById('pnt').value = settings.pnt;
        document.getElementById('pct').value = settings.pct;
        document.getElementById('rat').value = settings.rat;
    }
    ttf();
}

function ttf(){ // time to finish
 sz=document.getElementById("wxh").value;
 pc=document.getElementById("pct").value;
 sc=document.getElementById("rat").selectedIndex;
 tmp=((pc/10)+sz**4)*(sc+1);
 var hs = Math.floor(tmp / 60 / 60);
 var ms = Math.floor(tmp / 60) - (hs * 60);
 var ss = tmp % 60;
 //console.log(sz,sc,tmp,'-time:',hs,ms,ss);
 let est='';
 if (tmp<=100){ est="mere seconds"; }
 if (tmp>100 && tmp<=300){ est="few minutes"; }
 if (tmp>300 && tmp<=2600){ est="half hour"; }
 if (tmp>2600 && tmp<=4000){ est="a few hours"; }
 if (tmp>4000 && tmp<=8000){ est="several hours"; }
 if (tmp>8000 && tmp<=10000){ est="many hours"; }
 if (tmp>10000 && tmp<=80000){ est="too many hours"; }
 if (tmp>80000){ est="maybe days?"; }
 document.getElementById("ttf").innerHTML=est;
}

function wipe(isNewGame = false){
    for (let i = 0; i < 40; i++) {
        localStorage.removeItem(`puzzProgressRow${i}`);
    }
    localStorage.removeItem("originalPuzzle");
    if(isNewGame) newg();
}

function loadGame() {
    // Reset the UI and game state.
    document.getElementById("circhelp").style.display = 'none';
    document.getElementById("circsetup").style.display = 'none';
    document.getElementById("spr").style.display = 'block';
    done = 0;

    const saveButton = document.getElementById('sgcirc');

    // Check for saved progress in localStorage.
    let originalPuzzle = gStore("originalPuzzle");

    // Backwards compatibility: Check for old cookie/localStorage saves.
    if (!originalPuzzle) {
        let legacyProg = gCook("prog") || gStore("prog");
        if (legacyProg) {
            originalPuzzle = legacyProg;
            sStore("originalPuzzle", compress(originalPuzzle));
            sCook("prog", "", -1); // Delete old cookie
            localStorage.removeItem("prog"); // Delete old localStorage item
        }
    }

    if (gStore("puzzProgressRow0")) {
        try {
            // If there's saved data, load it.
            const firstRow = decompress(gStore("puzzProgressRow0"));
            const parts = firstRow.split('!');
            xx = parseInt(parts[0], 10);
            const szxy = parts[parts.length - 1].split('=')[0].split('x');
            yy = parseInt(szxy[1], 10) + 1;

            grid = Array(xx).fill(null).map(() => Array(yy).fill(null));

            // Apply any changed rows.
            for (let i = 0; i < xx; i++) {
                const changedRow = decompress(gStore(`puzzProgressRow${i}`));
                const rowParts = changedRow.split('!');
                for (let j = 1; j < rowParts.length; j++) {
                    const temp = rowParts[j].split('=');
                    const xy = temp[0].split('x');
                    grid[xy[0]][xy[1]] = temp[1];
                }
            }
            scale();
            main();
            saveButton.textContent = '-Save Game-';
            saveButton.disabled = true;
        } catch (e) {
            console.error("Failed to load saved data. Wiping and starting new game.", e);
            wipe(); // Wipe corrupted data
            return; // Exit and restart via wipe()
        }
    } else {
        // If no saved data, do nothing. The user will be presented with a blank screen
        // and can start a new game.
        saveButton.textContent = '-Save Game-';
        saveButton.disabled = true;
    }
}

function newg() {
        // If no saved data, generate a new puzzle.
        const rat = document.getElementById("rat").value * 1;
        const ts = document.getElementById("wxh").value * 1;
        const tx = window.innerWidth;
        const ty = window.innerHeight;
        let th, tw;

        if (rat) {
            if (tx > ty) {
                th = ts;
                tw = tx / (ty / ts);
            } else {
                tw = ts;
                th = ty / (tx / ts);
            }
        } else {
            tw = ts;
            th = ts;
        }

        const options = {
            wdh: Math.floor(tw),
            hgt: Math.floor(th),
            mov: document.getElementById('mov').value,
            rot: document.getElementById('rot').value,
            clr: document.getElementById('clr').value,
            pnt: document.getElementById('pnt').value,
            pct: document.getElementById('pct').value,
            rat: document.getElementById('rat').value
        };

        const puzzleData = generatePuzzle(options);
        dbstart(puzzleData);
}

function dbstart(data) {
    // Process the generated puzzle data.
    xx = data.xx * 1;
    yy = data.yy * 1;

    grid = new Array(xx).fill(null).map(() => new Array(yy).fill(null));
    for (let y = 0; y < yy; y++) {
        for (let x = 0; x < xx; x++) {
            const val = data.grid[`grid[${x}][${y}]`];
            // Check for and remove islands (pieces with no connections).
            grid[x][y] = (val !== '000000' && val.substr(2, 4) === '0000') ? '000000' : val;
        }
    }

    // Save each row to localStorage.
    for (let i = 0; i < xx; i++) {
        let rowStr = "";
        if (i === 0) {
            rowStr += xx;
        }
        for (let j = 0; j < yy; j++) {
            rowStr += `!${i}x${j}=${grid[i][j]}`;
        }
        sStore(`puzzProgressRow${i}`, compress(rowStr));
    }

    sStore('originalPuzzle', compress(xx + grid.flat().reduce((acc, val, index) => {
        const x = Math.floor(index / yy);
        const y = index % yy;
        return acc + `!${x}x${y}=${val}`;
    }, '')));


    scale();
    main();
    const saveButton = document.getElementById('sgcirc');
    saveButton.textContent = '-Save Original-';
    saveButton.disabled = false;
}

function butt(x){
 s=document.getElementById('wxh');
 m=document.getElementById('mov');
 r=document.getElementById('rot');
 c=document.getElementById('clr');
 p=document.getElementById('pct');
 f=document.getElementById('pnt');
 t=document.getElementById('rat');
 s.value=lvl[x].substr(0,2);
 m.value=lvl[x].substr(2,1);
 r.value=lvl[x].substr(3,1);
 c.value=lvl[x].substr(4,1);
 f.value=lvl[x].substr(5,1);
 p.value=lvl[x].substr(6,2);
 t.selectedIndex=lvl[x].substr(8,1);
 //if (document.getElementById('file')){
  //document.getElementById('file').remove();
 //}
 ttf();
}

function debug(t){
// use debug(time-in-ms,arg,arg,etc) to display popup messages
 clearTimeout(dbtm);
 if (!dbug){
  dbug=document.createElement('div'); dbug.id="dbug";document.body.appendChild(dbug);
 }
 for (var x in arguments){
  if (x!=0){dbug.innerHTML=arguments[x]+'<br>';}
 }
 dbtm=setTimeout(function(){dbug.remove();dbug='';}, t);
}

function clku(evn){
 if (done) { return; }
  tx=Math.floor((mx/ww)*xx); ty=Math.floor((my/hh)*yy);
 //console.log('UU',fx,fy,mx,my,drag,gx,gy,tx,ty);
 if (fx+'x'+fy+'x'+gx+'x'+gy==mx+'x'+my+'x'+tx+'x'+ty){
  //click only
  //console.log('rotate function');
  if (grid[gx][gy].charAt(1)>'0' && !evn.changedTouches){
   //rotate
   rotate(gx,gy,grid[gx][gy].charAt(1));
  }
 }
 //console.log(evn.changedTouches);
 if (drag!='n') {
  if(tx+''+ty!=gx+''+gy){
   if (grid[gx][gy].charAt(0)=='2'){
    if (grid[tx][ty].charAt(0)=='0'){
     grid[tx][ty]=grid[gx][gy];
     grid[gx][gy]='000000';
    }
   }
   if (grid[gx][gy].charAt(0)=='3'){
    if (grid[gx][ty].charAt(0)=='0'){
     grid[gx][ty]=grid[gx][gy];
     grid[gx][gy]='000000';
    }
   }
   if (grid[gx][gy].charAt(0)=='4'){
    if (grid[tx][gy].charAt(0)=='0'){
     grid[tx][gy]=grid[gx][gy];
     grid[gx][gy]='000000';
    }
   }
   //solve();
  }
 drag='n';
 }

  // Save the updated rows to localStorage.
  const sourceRow = gx;
  const destRow = tx;
  let sourceRowStr = "";
  if (sourceRow === 0) {
    sourceRowStr += xx;
  }
  for (let j = 0; j < yy; j++) {
    sourceRowStr += `!${sourceRow}x${j}=${grid[sourceRow][j]}`;
  }
  sStore(`puzzProgressRow${sourceRow}`, compress(sourceRowStr));

  if (sourceRow !== destRow) {
      let destRowStr = "";
      if (destRow === 0) {
        destRowStr += xx;
      }
      for (let j = 0; j < yy; j++) {
        destRowStr += `!${destRow}x${j}=${grid[destRow][j]}`;
      }
      sStore(`puzzProgressRow${destRow}`, compress(destRowStr));
  }
 //console.log(document.cookie);
 draw(1);
 stx = spr.getContext('2d');
 stx.clearRect(0, 0, can.width, can.height);
 gx=tx; gy=ty;
 //db.value='u:'+gx+'x'+gy;
 if (solve()!=1) {
  done=1;
  setTimeout(fini, 300);
  //fini();
 }
}
function clkd(evn){
 if (done) { return; }
 //evn.preventDefault();
 if (evn.changedTouches){
  var rect = can.getBoundingClientRect();
  mx=Math.floor(evn.changedTouches[0].clientX-rect.left);
  my=Math.floor(evn.changedTouches[0].clientY-rect.top);
 }
 fx=mx;fy=my;
 gx=Math.floor((mx/ww)*xx); gy=Math.floor((my/hh)*yy);
 //console.log('DD',mx,my,"g",gx,gy);
 //db.value='d:'+gx+'x'+gy;
 //console.log(grid[gx][gy]);
 if (grid[gx][gy].charAt(0)>1) {
  drag='y';
 }
}
function movr(evn){
 if (done) { return; }
 //evn.preventDefault();
 mx=evn.offsetX; my=evn.offsetY;
 if (evn&& !mx){
  //console.log("f",fx,fy,"g",gx,gy);
  var rect = can.getBoundingClientRect();
  mx=Math.floor(evn.changedTouches[0].clientX-rect.left);
  my=Math.floor(evn.changedTouches[0].clientY-rect.top);
 }
 //console.log('m:',mx,my,drag,"f",fx,fy,"g",gx,gy);
 if (drag=='n'){
  gx=Math.floor((mx/ww)*xx); gy=Math.floor((my/hh)*yy);
 } else { draw(); }
 //document.getElementById('debug').value=mx+'x'+my+' : '+gx+'x'+gy;

 //db.value=drag+':'+gx+'x'+gy;
}
function main(){
 //db=document.getElementById('debug');
 spr.onmousedown = clkd;
 spr.onmouseup = clku;
 spr.onmousemove = movr;
 spr.addEventListener("touchstart", clkd, {passive: true});
 spr.addEventListener("touchend", clku, false);
 //spr.addEventListener("touchcancel", handleCancel, false);
 spr.addEventListener("touchmove", movr, {passive: true});
 draw();
}
function scale(){
 var iw=window.innerWidth;
 var ih=window.innerHeight-(document.getElementById('hdr').getBoundingClientRect().height*3);
 //ratio >1=hori <1=vert
 var sc1=iw/ih;
 var sc2=xx/yy;
 //console.log(sc1,sc2);
 if (sc2!=1 && ( (sc1>1 && sc2<1) || (sc1<1 && sc2>=1) ) ) {
  //console.log('flip');
  var tgrd = new Array(yy).fill(null).map(()=>new Array(xx).fill(null));
  for (var y=0;y<yy;y++){
   for (var x=0;x<xx;x++){
    //console.log(y,x,grid[x][y].slice(0,1));
    //if first digit 3/4 chg to 4/3
    var t1=grid[x][y].slice(0,1);
    var t2=grid[x][y].slice(1,2);
    if (t1 === '3') {t1 = '4';}
    else if (t1 === '4') {t1 = '3';}
    if (t2 === '2') {t2 = '3';}
    else if (t2 === '3') {t2 = '2';}
    // Correctly swap the color tags for rotation.
    const pos = grid[x][y];
    tgrd[y][x] = t1 + t2 + pos.charAt(3) + pos.charAt(4) + pos.charAt(5) + pos.charAt(2);
   }
   tgrd[y].reverse();
  }
  xx=grid[0].length
  yy=grid.length
  grid=tgrd;
  sc2=xx/yy;
    // Clear all old progress rows to prevent stale data from being loaded.
    for (let i = 0; i < 40; i++) {
        localStorage.removeItem(`puzzProgressRow${i}`);
    }

    for (let i = 0; i < xx; i++) {
        let rowStr = "";
        if (i === 0) {
            rowStr += xx;
        }
        for (let j = 0; j < yy; j++) {
            rowStr += `!${i}x${j}=${grid[i][j]}`;
        }
        sStore(`puzzProgressRow${i}`, compress(rowStr));
    }
 }
 var tv=sc1>sc2 ? yy : xx;
 var tz=window.innerWidth/tv*scal;
 ww=tz*xx;
 hh=tz*yy;
 if (sc1>sc2){
  //console.log('scr land');
  ww=ih/yy*xx*scal;
  hh=ih/yy*yy*scal;
 }else{
  //console.log('scr port');
  ww=iw/xx*xx*scal;
  hh=iw/xx*yy*scal;
 }

 //console.log(sc1,sc2)
 //console.log(xx,yy,ww,hh,sc1,sc2);

 xxx=ww/xx;yyy=hh/yy;
 sz=xxx<yyy ? xxx*0.48 : yyy*0.48;
 var sc=document.getElementById("rat").selectedIndex;
 spr.width=ww; spr.height=hh;
 can.width=ww; can.height=hh;
 wrp.style.height=(hh+5)+'px';
 draw(1);
}
function draw(pri=0){ //priority, drag low, drop high.

 var fc= new Date();
 var fps = 1000 / (fc - fo);
 fo = fc;
 if (fps<30 && pri<1) { return; } //skip low FPS
 //debug(2000,fps.toFixed(1));
 //console.log(drag,gx,gy);
 ctx = can.getContext('2d');
 //ctx.clearRect(0, 0, can.width, can.height);
   ctx.fillStyle = "black";
   ctx.fillRect(0, 0, can.width, can.height);
 if (px){
  gx=px;gy=py;
 }
 for (y = 0; y < yy; y++) {
  for (x = 0; x < xx; x++) {
   if (drag=='y' && y==gy && x==gx){
    var stx = spr.getContext('2d');
    stx.clearRect(0, 0, can.width, can.height);
    if (grid[gx][gy].charAt(0)=='2'){
     drci(sz,mx,my,grid[x][y],1);
    }
    if (grid[gx][gy].charAt(0)=='3'){
     drci(sz,(x*xxx)+(xxx/2),my,grid[x][y],1);
    }
    if (grid[gx][gy].charAt(0)=='4'){
     drci(sz,mx,(y*yyy)+(yyy/2),grid[x][y],1);
    }
   }else{
    drci(sz,(x*xxx)+(xxx/2),(y*yyy)+(yyy/2),grid[x][y]);
   }
   ctx.lineWidth = 3;
   ctx.strokeStyle = "green";
   ctx.strokeRect(x*xxx, y*yyy, xxx, yyy);
  }
 }
}
function rd(x,y=0){
 return Math.floor(Math.random()*x)+y;
}
function rotate(x,y,t=1){
 pos=grid[x][y];
 if (t==='1'){
  grid[x][y]=pos.charAt(0)+pos.charAt(1)+pos.charAt(5)+pos.charAt(2)+pos.charAt(3)+pos.charAt(4);
 }
 if (t==='2'){
  grid[x][y]=pos.charAt(0)+pos.charAt(1)+pos.charAt(2)+pos.charAt(5)+pos.charAt(4)+pos.charAt(3);
 }
 if (t==='3'){
  grid[x][y]=pos.charAt(0)+pos.charAt(1)+pos.charAt(4)+pos.charAt(3)+pos.charAt(2)+pos.charAt(5);
 }
 //console.log(grid[x][y]);
}
function gc(cc){
 //console.log(cc);
//$col='grybvcplei';
 var o='ivory';
 if (cc=='g'){ o='green' }
 if (cc=='r'){ o='red' }
 if (cc=='y'){ o='yellow' }
 if (cc=='b'){ o='blue' }
 if (cc=='v'){ o='blueviolet' }
 if (cc=='c'){ o='cyan' }
 if (cc=='p'){ o='darkorange' }
 if (cc=='l'){ o='limegreen' }
 if (cc=='e'){ o='grey' }
 return o;
}
function drci(rad,x,y,p,s=0) {
 if (rad<4) { return; }
 ol='gray';
 pp=p.toString().padStart(4,'0');
 //console.log(pp);
 if (s==1){
 tmp = spr.getContext('2d');
 }else{
 tmp = can.getContext('2d');
 }
 if (pp.charAt(0)>0) {
 //console.log('big');
  tmp.beginPath();

  tmp.arc(x, y, rad-3, 0, 2 * Math.PI, false);
  tmp.fillStyle = gc(col.charAt(0));
  tmp.fill();
  tmp.beginPath();
  tmp.arc(x, y, rad-3, 0, 2 * Math.PI);
  tmp.strokeStyle = s==1 ? 'red' : ol;
  tmp.lineWidth = 3;
  tmp.stroke();

 rx=rad/3;
 $i=0;

  //drag: 0=blank 1=fixed 2=move:+ 3=LR:- 4=UD:|
  if (pp.charAt($i)=='2' || pp.charAt($i)=='3') {
   tmp.beginPath();
   tmp.strokeStyle = 'black';
   tmp.moveTo(x, y-(rad/3));
   tmp.lineTo(x,y+(rad/3));
   tmp.stroke();
  }
  if (pp.charAt($i)=='2' || pp.charAt($i)=='4') {
   tmp.beginPath();
   tmp.strokeStyle = 'black';
   tmp.moveTo(x-(rad/3), y);
   tmp.lineTo(x+(rad/3), y);
   tmp.stroke();
  }

 $i++;
 if (pp.charAt($i)!='0') {
  //click: 0=nothing 1=rotate:O 2=flipH:U 3=flipV:C
  if (pp.charAt($i)=='1') {
   tmp.beginPath();
   tmp.arc(x, y, rad/2, 0, 2 * Math.PI);
   tmp.strokeStyle = 'black';
   tmp.lineWidth = 3;
   tmp.stroke();
  }
  if (pp.charAt($i)=='2') {
   tmp.beginPath();
   tmp.arc(x, y, rad/2, 0, 1 * Math.PI);
   tmp.strokeStyle = 'black';
   tmp.lineWidth = 3;
   tmp.stroke();
  }
  if (pp.charAt($i)=='3') {
   tmp.beginPath();
   tmp.arc(x, y, rad/2, 1.5, 1.5 * Math.PI);
   tmp.strokeStyle = 'black';
   tmp.lineWidth = 3;
   tmp.stroke();
  }

 }
  $i++;
 //2+: tag colors 0=null ryvb
 if (pp.charAt($i)!='0') {
  //console.log('left');

  tmp.beginPath();
  tmp.arc(x-rad, y, rx, 1.5 * Math.PI, .5 * Math.PI, false);
  tmp.fillStyle = gc(pp.charAt($i));
  tmp.fill();
  tmp.beginPath();
  tmp.arc(x-rad, y, rx, 1.5 * Math.PI, .5 * Math.PI, false);
  tmp.strokeStyle = ol;
  tmp.stroke();
 }
 $i++;
 if (pp.charAt($i)!='0') {
  //console.log('up');

  tmp.beginPath();
  tmp.arc(x, y-rad, rx, 0, 1 * Math.PI, false);
  tmp.fillStyle = gc(pp.charAt($i));
  tmp.fill();
  tmp.beginPath();
  tmp.arc(x, y-rad, rx, 0, 1 * Math.PI, false);
  tmp.strokeStyle = ol;
  tmp.stroke();
 }
 $i++;
 if (pp.charAt($i)!='0') {
  //console.log('righ');

  tmp.beginPath();
  tmp.arc(x+rad, y, rx, .5 * Math.PI, 1.5 * Math.PI, false);
  tmp.fillStyle = gc(pp.charAt($i));
  tmp.fill();
  tmp.beginPath();
  tmp.arc(x+rad, y, rx, .5 * Math.PI, 1.5 * Math.PI, false);
  tmp.strokeStyle = ol;
  tmp.stroke();
}
$i++;
 if (pp.charAt($i)!='0') {
  //console.log('down');

  tmp.beginPath();
  tmp.arc(x, y+rad, rx, 1 * Math.PI, 2 * Math.PI, false);
  tmp.fillStyle = gc(pp.charAt($i));
  tmp.fill();
  tmp.beginPath();
  tmp.arc(x, y+rad, rx, 1 * Math.PI, 2 * Math.PI, false);
  tmp.strokeStyle = ol;
  tmp.stroke();
  }
 }
}
function solve(){
 var bit,chk,ii,tt;
 for (y = 0; y < yy; y++) {
  for (x = 0; x < xx; x++) {
   tt=0; tmp=grid[x][y].substr(2);
   //console.log(x,y,tmp);
   if (grid[x][y].charAt(0)>0){
    ii=0; bit=tmp.charAt(ii);
    if (bit!='0' && x>0) {
     //left console.log(tmp.charAt(0));
      chk=grid[x-1][y].substr(4,1);
      //console.log('l',x,y,bit,chk);
      if (bit!=chk) { return 1; }
      tt++;
    }
    ii++; bit=tmp.charAt(ii);
    if (bit!='0' && y>0) {
     //up console.log(tmp.charAt(1));
      chk=grid[x][y-1].substr(5,1);
      //console.log('u',x,y,bit,chk);
      if (bit!=chk) { return 1; }
      tt++;
    }
    ii++; bit=tmp.charAt(ii);
    if (bit!='0' && x<(xx-1)) {
     //right console.log(tmp.charAt(2));
      chk=grid[x+1][y].substr(2,1);
      //console.log('r',x,y,bit,chk);
      if (bit!=chk) { return 1; }
      tt++;
    }
    ii++; bit=tmp.charAt(ii);
    if (bit!='0' && y<(yy-1)) {
     //down console.log(tmp.charAt(3));
      chk=grid[x][y+1].substr(3,1);
      //console.log('r',x,y,bit,chk);
      if (bit!=chk) { return 1; }
      tt++;
    }
    if (tt<1) { return 1; }
   }
   //console.log('tt',tt);
  }
 }
 return 0;
}
function fini(){
    for (let i = 0; i < 40; i++) {
        localStorage.removeItem(`puzzProgressRow${i}`);
    }
    localStorage.removeItem("originalPuzzle");
 var elem = document.getElementById("spr");
 //elem.remove();
 elem.style.display='none';
 var msg='Congrats you won!\n\nTry a new puzzle, change some settings!\n\nYou can now save this image to share with others!\n\n';
 //sav(msg);
 alert(msg);
 return;
}

function sav(msg = 'Click Ok to save this game.', sav = 0) {
    var aa = document.createElement('a');
    var temp = "";
    if (sav == 1) {
        // To assemble a valid save file, we must reconstruct the full puzzle string.
        // Each `puzzProgressRow` is stored compressed and contains data for only one column,
        // including a prepended size identifier (e.g., "15!0x0=...").
        // A simple concatenation of these compressed chunks would be invalid.
        // Therefore, we decompress each chunk, assemble the full plaintext string,
        // and then recompress it once to create a valid, downloadable file.
        let fullPuzzleString = decompress(gStore('puzzProgressRow0'));
        for (let i = 1; i < xx; i++) {
            let columnData = decompress(gStore(`puzzProgressRow${i}`));
            fullPuzzleString += columnData.substring(columnData.indexOf('!'));
        }
        temp = fullPuzzleString;
    } else {
        const originalPuzzle = gStore('originalPuzzle');
        if (!originalPuzzle) {
            console.error("No original puzzle found to save.");
            return;
        }
        // When saving the original puzzle, always use the stored string.
        temp = decompress(originalPuzzle);
    }
    aa.href = 'data:attachment/text,' + encodeURI(compress(temp));
    aa.target = '_blank';
    aa.download = 'circles.dbs';
    aa.id = 'dl';
    var yn = confirm(msg);
    if (yn == true) {
        aa.click();
    }
    return;
}

//localStorage
function sStore(name, value) {
    localStorage.setItem(name, value);
}

function gStore(name) {
    return localStorage.getItem(name);
}

//cookies
function sCook(cname, cvalue, exdays=999) {
 if (cvalue.length>4096){ console.log('Cannot save huge levels in cookies!'); return; }
  const d = new Date();
  d.setTime(d.getTime() + (exdays*24*60*60*1000));
  let expires = "expires="+ d.toUTCString();
  document.cookie = cname + "=" + cvalue + ";" + expires + ";path=/";
  //console.log(cvalue.length);
}
function gCook(cname) {
  let name = cname + "=";
  let decodedCookie = decodeURIComponent(document.cookie);
  let ca = decodedCookie.split(';');
  for(let i = 0; i <ca.length; i++) {
    let c = ca[i];
    while (c.charAt(0) == ' ') {
      c = c.substring(1);
    }
    if (c.indexOf(name) == 0) {
      return c.substring(name.length, c.length);
    }
  }
  return "";
}

//load file ??

function loadr(event){
 //readFile();
 file=this.files[0];
 const reader = new FileReader();
 reader.addEventListener('load', (event) => {
  const result = decompress(event.target.result);
  const parts = result.split('!');
  const szxy = parts[parts.length - 1].split('=')[0].split('x');
  xx = parseInt(parts[0], 10);
  yy = parseInt(szxy[1], 10) + 1;
  let grid = Array(xx).fill(null).map(() => Array(yy).fill(null));
  for (let i = 1; i < parts.length; i++) {
    const temp = parts[i].split('=');
    const xy = temp[0].split('x');
    grid[xy[0]][xy[1]] = temp[1];
  }
  sStore('originalPuzzle', compress(result));
  for (let i = 0; i < xx; i++) {
    let rowStr = "";
    if (i === 0) {
        rowStr += xx;
    }
    for (let j = 0; j < yy; j++) {
        rowStr += `!${i}x${j}=${grid[i][j]}`;
    }
    sStore(`puzzProgressRow${i}`, compress(rowStr));
  }
  loadGame();
 });
 reader.readAsText(file);
}
function openFileDialog(accept, callback) {
 var inputElement = document.createElement("input");
 inputElement.type = "file";
 inputElement.accept = accept;
 inputElement.addEventListener("change", callback);
 inputElement.dispatchEvent(new MouseEvent("click"));
}

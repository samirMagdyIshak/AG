﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using AG;
using AG.Models;
using AG.DTO;
using Microsoft.AspNetCore.Authorization;
using AutoMapper;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace AG.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = "Bearer")]
    public class PhotosController : ControllerBase
    {
        private readonly AppContext _context;
        private readonly IMapper mapper;
        private readonly UserManager<AppUser> userManager;

        public PhotosController(AppContext context,IMapper mapper
                               ,UserManager<AppUser> userManager)
            
        {
            _context = context;
            this.mapper = mapper;
            this.userManager = userManager;
        }

        // GET: api/Photos
        [HttpGet]
        public async Task<ActionResult<IEnumerable<PhotoDto>>> Getphotos()
        {
            var email = HttpContext.User.FindFirst(ClaimTypes.Email)?.Value;
            var user = await userManager.FindByEmailAsync(email);
            var UserId = user.Id;
            var result =await _context.photos.Where(p=>p.UserId==UserId).ToListAsync();
           return mapper.Map<List<PhotoDto>>(result);
           
        }

        // GET: api/Photos/5
        [HttpGet("{id}")]
        public async Task<ActionResult<PhotoDto>> GetPhoto(int id)
        {
          
            var photo = await _context.photos.FindAsync(id);

            if (photo == null)
            {
                return NotFound();
            }

            return mapper.Map<PhotoDto>(photo);
        }

        //Get :api/Photos/today
        [HttpGet("today")]
        public  async Task<IActionResult> GetPhoto()
        {
            var email = HttpContext.User.FindFirst(ClaimTypes.Email)?.Value;
            var user = await userManager.FindByEmailAsync(email);
            var UserId = user.Id;
            var today = DateTime.Today;
           var result= await _context.photos.Where(p => p.Date.Day == today.Day&&p.Date.Month==today.Month&&p.Date.Year==today.Year && p.UserId==UserId).ToListAsync();

            return Ok(mapper.Map<List<PhotoDto>>(result)) ;  
        }
      
        // POST: api/Photos
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPost]
        public async Task<IActionResult> PostPhoto(PhotoDto photo)
        {
            var photoDB = new Photo { photo = photo.photo,Date = photo.Date};

            var email = HttpContext.User.FindFirst(ClaimTypes.Email)?.Value;
            var user = await userManager.FindByEmailAsync(email);
            photoDB.UserId = user.Id;
            photoDB.User=user;

            _context.photos.Add(photoDB);
            await _context.SaveChangesAsync();
            return NoContent();
        }

        // DELETE: api/Photos/5
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeletePhoto(int id)
        {
            var photo = await _context.photos.FindAsync(id);
            if (photo == null)
            {
                return NotFound();
            }

            _context.photos.Remove(photo);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        private bool PhotoExists(int id)
        {
            return _context.photos.Any(e => e.Id == id);
        }

        //for AI admin
        [Authorize(AuthenticationSchemes = "Bearer", Policy = "aiAdmin")]
        [HttpGet("AfterDate")]
        public async Task<IActionResult> GetPhoto(DateTime date)
        {
            //var result = await _context.photos.Where(p => p.Date.Day > date.Day && p.Date.Month >= date.Month && p.Date.Year >= date.Year ).ToListAsync();
            var result = await _context.photos.Where(p => p.Date>date ).ToListAsync();

            return Ok(mapper.Map<List<PhotoDto>>(result));
        }
        [Authorize(AuthenticationSchemes = "Bearer",Policy ="aiAdmin")]
        [HttpGet("All")]
        public async Task<IActionResult> GetALLPhoto()
        {
            var result = await _context.photos.ToListAsync();

            return Ok(mapper.Map<List<PhotoDto>>(result));
        }

        //for Embedded admin 
        [Authorize(AuthenticationSchemes = "Bearer", Policy = "embeddedAdmin")]
        [HttpPost("hardware")]
        public async Task<IActionResult> post(PhotoDto photo,string hardwareNum)
        {
            var photoDB = new Photo { photo = photo.photo, Date = photo.Date };
            var user = _context.hardwareInfo.Include(x => x.User).SingleOrDefault(h => h.HardwareNum == hardwareNum)?.User;
            if (user == null) return BadRequest("the hardwareNum is incorrect");
            photoDB.UserId = user.Id;
            photoDB.User = user;

            _context.photos.Add(photoDB);
            await _context.SaveChangesAsync();
            return NoContent();
        }
    }
}
